"""
Vulnerability intelligence engine.

Sources: NVD (CVE API 2.0), OSV.dev, CISA KEV catalog, GitHub Security Advisories.
Every field is attributed to the source it came from. Per-source status is one of:
  ok | not_found | unavailable (network/API error) | skipped (not applicable)
"unavailable" is never conflated with a negative result (e.g. KEV membership is
NULL — unknown — when the KEV catalog could not be loaded).
"""

import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.loop_lock import LoopLock
from app.db.models import Finding, IntelSyncState, KEVEntry, VulnerabilityRecord


class _RateLimiter:
    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = LoopLock()

    async def wait(self):
        async with self._lock:
            delta = time.monotonic() - self._last
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self._last = time.monotonic()


# NVD: 5 requests / 30s without a key, 50 / 30s with one.
_nvd_limiter = _RateLimiter(0.7 if settings.NVD_API_KEY else 6.2)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(v: Optional[str]) -> Optional[datetime]:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def _get_json(url: str, *, headers=None, params=None) -> tuple[Optional[Any], str]:
    try:
        async with httpx.AsyncClient(timeout=settings.INTEL_HTTP_TIMEOUT, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "TRACE", **(headers or {})}, params=params)
        if r.status_code == 404:
            return None, "not_found"
        if r.status_code >= 400:
            return None, f"unavailable: HTTP {r.status_code}"
        return r.json(), "ok"
    except (httpx.HTTPError, ValueError) as e:
        return None, f"unavailable: {type(e).__name__}"


# --------------------------------------------------------------------------- sources


async def fetch_nvd(cve_id: str) -> tuple[Optional[Dict], str]:
    await _nvd_limiter.wait()
    headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else None
    data, status = await _get_json(settings.NVD_API_URL, headers=headers, params={"cveId": cve_id})
    if status != "ok":
        return None, status
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None, "not_found"
    cve = vulns[0]["cve"]
    metrics = cve.get("metrics") or {}
    score = vector = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            cd = m.get("cvssData", {})
            score, vector = cd.get("baseScore"), cd.get("vectorString")
            severity = cd.get("baseSeverity") or m.get("baseSeverity")
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")})
    refs = [{"url": r["url"], "source": "nvd", "tags": r.get("tags", [])} for r in cve.get("references", [])]
    products = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if cm.get("vulnerable"):
                    products.append({k: cm.get(k) for k in ("criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if cm.get(k)})
    return {
        "description": desc, "cvss_score": score, "cvss_vector": vector, "cvss_severity": severity, "cwe_ids": cwes,
        "published": cve.get("published"), "modified": cve.get("lastModified"), "references": refs,
        "affected_products": products[:50], "vuln_status": cve.get("vulnStatus"),
    }, "ok"


async def fetch_osv(vuln_id: str) -> tuple[Optional[Dict], str]:
    return await _get_json(f"{settings.OSV_API_URL}/vulns/{vuln_id}")


async def fetch_ghsa(vuln_id: str, aliases: List[str]) -> tuple[Optional[Dict], str]:
    from app.integrations.github import _headers

    headers = _headers(settings.GITHUB_TOKEN)
    ghsa = next((a for a in [vuln_id, *aliases] if a and a.upper().startswith("GHSA-")), None)
    if ghsa:
        return await _get_json(f"{settings.GITHUB_API_URL}/advisories/{ghsa}", headers=headers)
    cve = next((a for a in [vuln_id, *aliases] if a and a.upper().startswith("CVE-")), None)
    if not cve:
        return None, "skipped"
    data, status = await _get_json(f"{settings.GITHUB_API_URL}/advisories", headers=headers, params={"cve_id": cve, "per_page": 1})
    if status != "ok":
        return None, status
    return (data[0], "ok") if data else (None, "not_found")


async def sync_kev(db: AsyncSession, force: bool = False) -> Dict[str, Any]:
    state = (await db.execute(select(IntelSyncState).where(IntelSyncState.source == "cisa_kev"))).scalar_one_or_none()
    if state and state.status == "ok" and not force and state.last_synced_at and _as_aware(state.last_synced_at) > _now() - timedelta(hours=settings.INTEL_CACHE_TTL_HOURS):
        return {"status": "cached", "count": state.record_count}
    data, status = await _get_json(settings.CISA_KEV_URL)
    if not state:
        state = IntelSyncState(source="cisa_kev")
        db.add(state)
    if status != "ok":
        state.status, state.detail = "error", status
        await db.flush()
        return {"status": status, "count": state.record_count or 0}
    existing = {k.cve_id: k for k in (await db.execute(select(KEVEntry))).scalars()}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        row = existing.get(cid) or KEVEntry(cve_id=cid)
        row.vendor, row.product, row.name = v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName")
        row.date_added, row.due_date, row.required_action = v.get("dateAdded"), v.get("dueDate"), v.get("requiredAction")
        row.known_ransomware, row.notes = v.get("knownRansomwareCampaignUse"), v.get("notes")
        if cid not in existing:
            db.add(row)
    state.status, state.last_synced_at = "ok", _now()
    state.record_count = len(data.get("vulnerabilities", []))
    state.detail = f"catalog {data.get('catalogVersion')}"
    await db.flush()
    return {"status": "ok", "count": state.record_count}


def _as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- aggregation


async def lookup(db: AsyncSession, vuln_id: str, aliases: Optional[List[str]] = None, refresh: bool = False) -> VulnerabilityRecord:
    """Return cached or freshly aggregated intelligence for a vulnerability identifier."""
    vuln_id = vuln_id.strip()
    rec = (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.vuln_id == vuln_id))).scalar_one_or_none()
    fresh = rec and rec.fetched_at and _as_aware(rec.fetched_at) > _now() - timedelta(hours=settings.INTEL_CACHE_TTL_HOURS)
    if rec and fresh and not refresh and all(not str(s.get("status", "")).startswith("unavailable") for s in (rec.sources or {}).values()):
        return rec

    aliases = list(aliases or [])
    sources: Dict[str, Dict[str, Any]] = {}
    fetched = _now().isoformat()

    osv, osv_status = await fetch_osv(vuln_id)
    sources["osv"] = {"status": osv_status, "fetched_at": fetched, "url": f"https://osv.dev/vulnerability/{vuln_id}"}
    if osv:
        aliases = sorted(set(aliases) | set(osv.get("aliases") or []))
    cve = vuln_id.upper() if vuln_id.upper().startswith("CVE-") else next((a for a in aliases if a.upper().startswith("CVE-")), None)

    nvd, nvd_status = (await fetch_nvd(cve)) if cve else (None, "skipped")
    sources["nvd"] = {"status": nvd_status, "fetched_at": fetched, "url": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None}

    ghsa, ghsa_status = await fetch_ghsa(vuln_id, aliases)
    sources["ghsa"] = {"status": ghsa_status, "fetched_at": fetched, "url": ghsa.get("html_url") if ghsa else None}

    kev_state = await sync_kev(db)
    kev_row = None
    if cve and kev_state["status"] in ("ok", "cached"):
        kev_row = (await db.execute(select(KEVEntry).where(KEVEntry.cve_id == cve))).scalar_one_or_none()
        sources["cisa_kev"] = {"status": "ok" if kev_row else "not_found", "fetched_at": fetched, "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}
        known_exploited: Optional[bool] = bool(kev_row)
    else:
        sources["cisa_kev"] = {"status": "skipped" if not cve else kev_state["status"], "fetched_at": fetched}
        known_exploited = None

    if not rec:
        rec = VulnerabilityRecord(vuln_id=vuln_id)
        db.add(rec)

    rec.aliases = aliases
    rec.summary = (osv or {}).get("summary") or (ghsa or {}).get("summary")
    rec.description = (nvd or {}).get("description") or (osv or {}).get("details") or (ghsa or {}).get("description")
    cvss = (ghsa or {}).get("cvss") or {}
    rec.cvss_score = (nvd or {}).get("cvss_score") or cvss.get("score")
    rec.cvss_vector = (nvd or {}).get("cvss_vector") or cvss.get("vector_string")
    rec.cvss_severity = ((nvd or {}).get("cvss_severity") or (ghsa or {}).get("severity") or "").upper() or None
    rec.cwe_ids = (nvd or {}).get("cwe_ids") or [c.get("cwe_id") for c in (ghsa or {}).get("cwes") or [] if c.get("cwe_id")]
    rec.published_at = _parse_dt((nvd or {}).get("published") or (osv or {}).get("published"))
    rec.modified_at = _parse_dt((nvd or {}).get("modified") or (osv or {}).get("modified"))

    affected, fixed = [], []
    for a in (osv or {}).get("affected") or []:
        pkg = a.get("package") or {}
        if not pkg.get("name"):
            continue
        # GIT ranges carry commit hashes, not package versions
        evs = [e for r in a.get("ranges") or [] if r.get("type") != "GIT" for e in r.get("events") or []]
        f = [e["fixed"] for e in evs if "fixed" in e]
        fixed += f
        affected.append({"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name"),
                         "introduced": [e["introduced"] for e in evs if "introduced" in e], "fixed": f, "source": "osv"})
    for v in (ghsa or {}).get("vulnerabilities") or []:
        if v.get("first_patched_version"):
            fixed.append(v["first_patched_version"])
    if not affected and nvd:
        affected = [{**p, "source": "nvd"} for p in nvd["affected_products"]]
    rec.affected, rec.fixed_versions = affected, sorted(set(fixed))

    refs: List[Dict[str, Any]] = []
    refs += (nvd or {}).get("references") or []
    refs += [{"url": r.get("url"), "source": "osv", "tags": [r.get("type")]} for r in (osv or {}).get("references") or []]
    if ghsa and ghsa.get("html_url"):
        refs.append({"url": ghsa["html_url"], "source": "ghsa", "tags": ["advisory"]})
    seen, dedup = set(), []
    for r in refs:
        if r.get("url") and r["url"] not in seen:
            seen.add(r["url"])
            dedup.append(r)
    rec.references = dedup[:60]
    rec.exploit_references = [r["url"] for r in dedup if any(t and "exploit" in t.lower() for t in r.get("tags") or [])]
    rec.is_known_exploited = known_exploited
    rec.kev = {k: getattr(kev_row, k) for k in ("vendor", "product", "name", "date_added", "due_date", "required_action", "known_ransomware")} if kev_row else None

    guidance = []
    if rec.fixed_versions:
        guidance.append(f"Upgrade to a fixed version: {', '.join(rec.fixed_versions[:6])} (source: OSV/GHSA).")
    if kev_row and kev_row.required_action:
        guidance.append(f"CISA required action: {kev_row.required_action}")
    rec.remediation = " ".join(guidance) or None
    rec.sources = sources
    rec.fetched_at = _now()
    await db.flush()
    return rec


async def enrich_findings(db: AsyncSession, repository_id: uuid.UUID, only_scan: Optional[uuid.UUID] = None, limit: int = 60) -> int:
    q = select(Finding).where(Finding.repository_id == repository_id, Finding.vuln_id.isnot(None))
    if only_scan:
        q = q.where(Finding.last_scan_id == only_scan)
    findings = (await db.execute(q)).scalars().all()
    ids: Dict[str, List[str]] = {}
    for f in findings:
        ids.setdefault(f.vuln_id, list(f.aliases or []))
    count = 0
    for vid, aliases in list(ids.items())[:limit]:
        try:
            rec = await lookup(db, vid, aliases)
            count += 1
            for f in findings:
                if f.vuln_id == vid and f.cvss_score is None and rec.cvss_score:
                    f.cvss_score = rec.cvss_score
            await db.commit()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"intel lookup {vid} failed: {e}")
    return count


def record_to_dict(rec: VulnerabilityRecord) -> Dict[str, Any]:
    return {
        "vuln_id": rec.vuln_id, "aliases": rec.aliases, "summary": rec.summary, "description": rec.description,
        "cvss_score": rec.cvss_score, "cvss_vector": rec.cvss_vector, "cvss_severity": rec.cvss_severity, "cwe_ids": rec.cwe_ids,
        "published_at": rec.published_at.isoformat() if rec.published_at else None,
        "modified_at": rec.modified_at.isoformat() if rec.modified_at else None,
        "affected": rec.affected, "fixed_versions": rec.fixed_versions, "references": rec.references,
        "exploit_references": rec.exploit_references, "is_known_exploited": rec.is_known_exploited, "kev": rec.kev,
        "remediation": rec.remediation, "sources": rec.sources,
        "fetched_at": rec.fetched_at.isoformat() if rec.fetched_at else None,
    }
