"""
Security RAG knowledge engine.

ingest -> normalize -> metadata -> chunk -> embed (Ollama) -> Qdrant (server or embedded)
retrieve = exact structured matches (VulnerabilityRecord) + hybrid (dense + BM25, fused with RRF)
           + metadata filters + heuristic rerank -> evidence with citation ids.

Retrieved text is untrusted: it is returned as quoted evidence and never treated as instructions.
"""

import asyncio
import hashlib
import math
import re
import threading
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.loop_lock import LoopLock
from app.db.models import RagChunk, RagDocument, RagSource, VulnerabilityRecord

# --------------------------------------------------------------------------- source catalog

_CS = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/"
_CS_WEB = "https://cheatsheetseries.owasp.org/cheatsheets/"
_T10 = "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/"
OWASP_CHEATSHEETS = [
    "SQL_Injection_Prevention", "OS_Command_Injection_Defense", "Deserialization", "Secrets_Management",
    "Docker_Security", "Vulnerable_Dependency_Management", "Cross_Site_Scripting_Prevention", "Input_Validation",
    "Server_Side_Request_Forgery_Prevention", "Django_Security", "Nodejs_Security", "LLM_Prompt_Injection_Prevention",
    "AI_Agent_Security", "Secure_AI_Model_Ops", "Authentication", "Authorization", "Logging", "Error_Handling",
]
OWASP_TOP10 = [
    "A01_2021-Broken_Access_Control", "A02_2021-Cryptographic_Failures", "A03_2021-Injection", "A04_2021-Insecure_Design",
    "A05_2021-Security_Misconfiguration", "A06_2021-Vulnerable_and_Outdated_Components",
    "A07_2021-Identification_and_Authentication_Failures", "A08_2021-Software_and_Data_Integrity_Failures",
    "A09_2021-Security_Logging_and_Monitoring_Failures", "A10_2021-Server-Side_Request_Forgery_(SSRF)",
]
DEFAULT_CWES = ["20", "22", "78", "79", "89", "94", "95", "200", "250", "287", "306", "352", "434", "489", "502", "611",
                "668", "732", "798", "862", "918", "1333", "1395", "1426", "1427"]

BUILTIN_SOURCES = [
    {"name": "OWASP Cheat Sheet Series", "source_type": "owasp", "url": "https://cheatsheetseries.owasp.org"},
    {"name": "OWASP Top 10 (2021)", "source_type": "owasp", "url": "https://owasp.org/Top10/"},
    {"name": "MITRE CWE", "source_type": "cwe", "url": "https://cwe.mitre.org"},
    {"name": "Vulnerability intelligence (NVD / OSV / GHSA / CISA KEV)", "source_type": "vuln_intel", "url": None},
]


# --------------------------------------------------------------------------- chunking / tokenizing

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_\-\.]*[a-z0-9]|[a-z0-9]")
_STOP = set("the a an and or of to in for on is are be by with as that this it from at can not use if into any".split())


def tokenize(text: str) -> List[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP]


def chunk_markdown(text: str, size: int = settings.RAG_CHUNK_SIZE, overlap: int = settings.RAG_CHUNK_OVERLAP) -> List[Dict[str, str]]:
    sections, heading, buf = [], "", []
    for line in text.splitlines():
        if re.match(r"^#{1,4}\s", line):
            if buf:
                sections.append((heading, "\n".join(buf).strip()))
            heading, buf = line.lstrip("# ").strip(), []
        else:
            buf.append(line)
    if buf:
        sections.append((heading, "\n".join(buf).strip()))
    chunks = []
    for heading, body in sections:
        if not body:
            continue
        start = 0
        while start < len(body):
            end = min(len(body), start + size)
            if end < len(body):
                cut = body.rfind("\n", start + size // 2, end)
                end = cut if cut > 0 else end
            piece = body[start:end].strip()
            if len(piece) > 40:
                chunks.append({"heading": heading, "text": (f"{heading}\n" if heading else "") + piece})
            if end >= len(body):
                break
            start = max(end - overlap, start + 1)
    return chunks


# --------------------------------------------------------------------------- embeddings / vector store


class Embedder:
    def __init__(self):
        self.model = settings.EMBEDDING_MODEL
        self.enabled = settings.EMBEDDING_PROVIDER == "ollama"
        self.dim: Optional[int] = None
        self.last_error: Optional[str] = None

    async def embed(self, texts: List[str], kind: str = "document") -> Optional[List[List[float]]]:
        if not self.enabled or not texts:
            return None
        prefix = "search_document: " if kind == "document" else "search_query: "
        if "nomic" not in self.model:
            prefix = ""
        out: List[List[float]] = []
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                for i in range(0, len(texts), 32):
                    r = await c.post(f"{settings.OLLAMA_BASE_URL}/api/embed",
                                     json={"model": self.model, "input": [prefix + t[:6000] for t in texts[i:i + 32]]})
                    r.raise_for_status()
                    out.extend(r.json()["embeddings"])
        except Exception as e:  # noqa: BLE001
            self.last_error = f"{type(e).__name__}: {e}"[:200]
            logger.warning(f"embedding failed: {self.last_error}")
            return None
        self.dim = len(out[0]) if out else self.dim
        self.last_error = None
        return out


class VectorStore:
    """Qdrant wrapper: server mode when QDRANT_URL is set, embedded on-disk mode otherwise."""

    _lock = threading.Lock()
    _client = None

    def client(self):
        with self._lock:
            if VectorStore._client is None:
                from qdrant_client import QdrantClient

                if settings.QDRANT_URL:
                    VectorStore._client = QdrantClient(url=settings.QDRANT_URL, api_key=settings.QDRANT_API_KEY, timeout=30)
                else:
                    import os

                    os.makedirs(settings.QDRANT_PATH, exist_ok=True)
                    VectorStore._client = QdrantClient(path=settings.QDRANT_PATH)
            return VectorStore._client

    @property
    def mode(self) -> str:
        return "server" if settings.QDRANT_URL else "embedded"

    def ensure(self, dim: int) -> None:
        from qdrant_client.models import Distance, PayloadSchemaType, VectorParams

        c = self.client()
        if not c.collection_exists(settings.QDRANT_COLLECTION):
            c.create_collection(settings.QDRANT_COLLECTION, vectors_config=VectorParams(size=dim, distance=Distance.COSINE))
            if self.mode == "server":  # embedded mode has no payload indexes
                for f in ("source_type", "vuln_ids", "cwe_ids", "document_id"):
                    c.create_payload_index(settings.QDRANT_COLLECTION, f, PayloadSchemaType.KEYWORD)

    def upsert(self, points: List[Dict[str, Any]]) -> None:
        from qdrant_client.models import PointStruct

        self.client().upsert(settings.QDRANT_COLLECTION, [PointStruct(id=p["id"], vector=p["vector"], payload=p["payload"]) for p in points])

    def delete_document(self, document_id: str) -> None:
        from qdrant_client.models import FieldCondition, Filter, FilterSelector, MatchValue

        c = self.client()
        if c.collection_exists(settings.QDRANT_COLLECTION):
            c.delete(settings.QDRANT_COLLECTION, points_selector=FilterSelector(filter=Filter(must=[FieldCondition(key="document_id", match=MatchValue(value=document_id))])))

    def search(self, vector: List[float], limit: int, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        from qdrant_client.models import FieldCondition, Filter, MatchAny

        c = self.client()
        if not c.collection_exists(settings.QDRANT_COLLECTION):
            return []
        must = [FieldCondition(key=k, match=MatchAny(any=v if isinstance(v, list) else [v])) for k, v in filters.items() if v]
        res = c.query_points(settings.QDRANT_COLLECTION, query=vector, limit=limit, query_filter=Filter(must=must) if must else None, with_payload=True)
        return [{"chunk_id": p.payload["chunk_id"], "score": p.score} for p in res.points]

    def count(self) -> int:
        c = self.client()
        if not c.collection_exists(settings.QDRANT_COLLECTION):
            return 0
        return c.count(settings.QDRANT_COLLECTION).count


embedder = Embedder()
store = VectorStore()


# --------------------------------------------------------------------------- BM25 index


class BM25Index:
    """Keyword index shared by all job threads. Rebuilds publish a complete snapshot in one assignment,
    so concurrent searches always see consistent docs/tf/df."""

    def __init__(self):
        self.version: Optional[str] = None
        self._snap: tuple = ([], [], Counter(), 0.0)

    @property
    def docs(self) -> List[Dict[str, Any]]:
        return self._snap[0]

    def build(self, rows: List[Dict[str, Any]], version: str) -> None:
        tfs, df = [], Counter()
        for r in rows:
            c = Counter(tokenize(r["text"]))
            tfs.append(c)
            df.update(c.keys())
        avgdl = sum(sum(c.values()) for c in tfs) / max(1, len(tfs))
        self._snap = (rows, tfs, df, avgdl)
        self.version = version

    def search(self, query: str, limit: int, allow: Optional[set] = None, k1: float = 1.5, b: float = 0.75) -> List[Dict[str, Any]]:
        docs, tfs, df, avgdl = self._snap
        q = tokenize(query)
        n = len(docs)
        scores = []
        for i, tf in enumerate(tfs):
            if allow is not None and docs[i]["chunk_id"] not in allow:
                continue
            dl = sum(tf.values()) or 1
            s = 0.0
            for t in q:
                if t in tf:
                    idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                    s += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * dl / avgdl))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [{"chunk_id": docs[i]["chunk_id"], "score": s} for s, i in scores[:limit]]


_bm25 = BM25Index()
_bm25_lock = LoopLock()


# --------------------------------------------------------------------------- ingestion


async def _get_source(db: AsyncSession, name: str, source_type: str, url: Optional[str], org_id=None, trust="authoritative") -> RagSource:
    src = (await db.execute(select(RagSource).where(RagSource.name == name, RagSource.organization_id == org_id))).scalar_one_or_none()
    if not src:
        src = RagSource(name=name, source_type=source_type, url=url, organization_id=org_id, trust_level=trust)
        db.add(src)
        await db.flush()
    return src


async def upsert_document(db: AsyncSession, source: RagSource, external_id: str, title: str, url: Optional[str], content: str,
                          metadata: Optional[Dict[str, Any]] = None) -> RagDocument:
    content = content.replace("\x00", "")
    h = hashlib.sha256(content.encode()).hexdigest()
    doc = (await db.execute(select(RagDocument).where(RagDocument.source_id == source.id, RagDocument.external_id == external_id))).scalar_one_or_none()
    if doc and doc.content_hash == h and doc.embedded:
        return doc
    if not doc:
        doc = RagDocument(source_id=source.id, external_id=external_id)
        db.add(doc)
    doc.title, doc.url, doc.content, doc.content_hash = title, url, content, h
    doc.doc_metadata = {**(metadata or {}), "source_type": source.source_type, "trust_level": source.trust_level}
    await db.flush()
    for old in (await db.execute(select(RagChunk).where(RagChunk.document_id == doc.id))).scalars():
        await db.delete(old)
    await db.flush()
    pieces = chunk_markdown(content)
    rows = []
    for i, p in enumerate(pieces):
        ch = RagChunk(id=uuid.uuid4(), document_id=doc.id, chunk_index=i, text=p["text"], chunk_metadata={"heading": p["heading"]})
        db.add(ch)
        rows.append(ch)
    doc.chunk_count = len(rows)
    vectors = await embedder.embed([r.text for r in rows], "document")
    if vectors:
        await asyncio.to_thread(_store_vectors, doc, source, rows, vectors)
        doc.embedded = True
    else:
        doc.embedded = False
    await db.flush()
    _bm25.version = None  # invalidate keyword index
    return doc


def _store_vectors(doc: RagDocument, source: RagSource, rows: List[RagChunk], vectors: List[List[float]]) -> None:
    store.ensure(len(vectors[0]))
    store.delete_document(str(doc.id))
    md = doc.doc_metadata or {}
    store.upsert([{
        "id": str(r.id), "vector": v,
        "payload": {"chunk_id": str(r.id), "document_id": str(doc.id), "source_type": source.source_type,
                    "vuln_ids": md.get("vuln_ids", []), "cwe_ids": md.get("cwe_ids", []), "title": doc.title,
                    "org_id": str(source.organization_id) if source.organization_id else None},
    } for r, v in zip(rows, vectors)])


async def _fetch_text(url: str) -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "TRACE"})
        return r.text if r.status_code == 200 else None
    except httpx.HTTPError:
        return None


def _clean_md(text: str) -> str:
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return re.sub(r"\n{3,}", "\n\n", text)


async def ingest_owasp(db: AsyncSession) -> Dict[str, Any]:
    ok, failed = 0, []
    cs = await _get_source(db, "OWASP Cheat Sheet Series", "owasp", "https://cheatsheetseries.owasp.org")
    for name in OWASP_CHEATSHEETS:
        text = await _fetch_text(f"{_CS}{name}_Cheat_Sheet.md")
        if not text:
            failed.append(name)
            continue
        await upsert_document(db, cs, f"cheatsheet:{name}", f"OWASP {name.replace('_', ' ')} Cheat Sheet",
                              f"{_CS_WEB}{name}_Cheat_Sheet.html", _clean_md(text), {"category": "cheatsheet"})
        ok += 1
        await db.commit()
    t10 = await _get_source(db, "OWASP Top 10 (2021)", "owasp", "https://owasp.org/Top10/")
    for name in OWASP_TOP10:
        text = await _fetch_text(f"{_T10}{name}.md")
        if not text:
            failed.append(name)
            continue
        cwes = sorted(set(re.findall(r"CWE-(\d+)", text)))
        await upsert_document(db, t10, f"top10:{name}", f"OWASP Top 10 {name.replace('_', ' ').replace('-', ' ')}",
                              f"https://owasp.org/Top10/{name.replace('(', '_').replace(')', '_')}/", _clean_md(text),
                              {"category": "top10", "cwe_ids": [f"CWE-{c}" for c in cwes][:80]})
        ok += 1
        await db.commit()
    for src in (cs, t10):
        await _finish_source(db, src, failed)
    return {"ingested": ok, "failed": failed}


async def ingest_cwes(db: AsyncSession, cwe_ids: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    src = await _get_source(db, "MITRE CWE", "cwe", "https://cwe.mitre.org")
    ok, failed = 0, []
    ids = sorted({str(c).upper().replace("CWE-", "") for c in (cwe_ids or DEFAULT_CWES)})
    async with httpx.AsyncClient(timeout=30) as c:
        for cid in ids:
            try:
                r = await c.get(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cid}")
                w = r.json()["Weaknesses"][0] if r.status_code == 200 else None
            except (httpx.HTTPError, ValueError, KeyError, IndexError):
                w = None
            if not w:
                failed.append(cid)
                continue
            parts = [f"# CWE-{cid}: {w.get('Name')}", w.get("Description", ""), w.get("ExtendedDescription") or ""]
            for cons in w.get("CommonConsequences") or []:
                parts.append(f"Consequence ({', '.join(cons.get('Scope', []))}): {', '.join(cons.get('Impact', []))}. {cons.get('Note') or ''}")
            mits = w.get("PotentialMitigations") or []
            if mits:
                parts.append("## Potential mitigations")
                parts += [f"- [{m.get('Phase', [''])[0] if m.get('Phase') else ''}] {m.get('Description', '')}" for m in mits[:10]]
            dm = w.get("DetectionMethods") or []
            if dm:
                parts.append("## Detection methods")
                parts += [f"- {d.get('Method')}: {d.get('Description', '')}" for d in dm[:6]]
            await upsert_document(db, src, f"CWE-{cid}", f"CWE-{cid}: {w.get('Name')}", f"https://cwe.mitre.org/data/definitions/{cid}.html",
                                  "\n\n".join(p for p in parts if p), {"cwe_ids": [f"CWE-{cid}"], "likelihood": w.get("LikelihoodOfExploit")})
            ok += 1
            await db.commit()
    await _finish_source(db, src, failed)
    return {"ingested": ok, "failed": failed}


async def ingest_vuln_records(db: AsyncSession) -> Dict[str, Any]:
    src = await _get_source(db, "Vulnerability intelligence (NVD / OSV / GHSA / CISA KEV)", "vuln_intel", None)
    n = 0
    for rec in (await db.execute(select(VulnerabilityRecord))).scalars():
        await upsert_document(db, src, rec.vuln_id, f"{rec.vuln_id}: {rec.summary or ''}"[:500],
                              (rec.sources or {}).get("osv", {}).get("url") or (rec.sources or {}).get("nvd", {}).get("url"),
                              vuln_record_text(rec), {"vuln_ids": [rec.vuln_id, *(rec.aliases or [])], "cwe_ids": rec.cwe_ids or [],
                                                      "packages": [a.get("package") for a in rec.affected or [] if a.get("package")]})
        n += 1
    await _finish_source(db, src, [])
    return {"ingested": n, "failed": []}


def vuln_record_text(rec: VulnerabilityRecord) -> str:
    lines = [f"# {rec.vuln_id}", f"Aliases: {', '.join(rec.aliases or []) or 'none'}"]
    if rec.summary:
        lines.append(f"Summary: {rec.summary}")
    if rec.description:
        lines.append(f"Description: {rec.description}")
    if rec.cvss_score is not None:
        lines.append(f"CVSS: {rec.cvss_score} ({rec.cvss_severity}) {rec.cvss_vector or ''}")
    if rec.cwe_ids:
        lines.append(f"Weaknesses: {', '.join(rec.cwe_ids)}")
    for a in (rec.affected or [])[:10]:
        if a.get("package"):
            lines.append(f"Affected: {a.get('ecosystem')}/{a.get('package')} introduced {a.get('introduced')} fixed {a.get('fixed')}")
    if rec.fixed_versions:
        lines.append(f"Fixed versions: {', '.join(rec.fixed_versions)}")
    kev = "unknown (KEV data unavailable)" if rec.is_known_exploited is None else ("YES — listed in CISA KEV" if rec.is_known_exploited else "not listed in CISA KEV")
    lines.append(f"Known exploited: {kev}")
    if rec.remediation:
        lines.append(f"Remediation: {rec.remediation}")
    return "\n".join(lines)


async def ingest_internal(db: AsyncSession, org_id, title: str, content: str, url: Optional[str] = None) -> RagDocument:
    src = await _get_source(db, "Internal security knowledge", "internal", None, org_id=org_id, trust="approved_internal")
    doc = await upsert_document(db, src, hashlib.sha1(title.encode()).hexdigest()[:16], title, url, content, {"category": "internal"})
    await _finish_source(db, src, [])
    return doc


async def _finish_source(db: AsyncSession, src: RagSource, failed: List[str]) -> None:
    from sqlalchemy import func

    src.document_count = (await db.execute(select(func.count(RagDocument.id)).where(RagDocument.source_id == src.id))).scalar()
    src.last_ingested_at = datetime.now(timezone.utc)
    src.status = "ok" if not failed else ("partial" if src.document_count else "error")
    src.detail = f"failed: {', '.join(failed[:20])}" if failed else None
    await db.flush()


async def reembed_missing(db: AsyncSession) -> int:
    docs = (await db.execute(select(RagDocument).where(RagDocument.embedded.is_(False)))).scalars().all()
    n = 0
    for doc in docs:
        src = await db.get(RagSource, doc.source_id)
        rows = (await db.execute(select(RagChunk).where(RagChunk.document_id == doc.id).order_by(RagChunk.chunk_index))).scalars().all()
        vectors = await embedder.embed([r.text for r in rows], "document")
        if not vectors:
            break
        await asyncio.to_thread(_store_vectors, doc, src, rows, vectors)
        doc.embedded = True
        n += 1
    await db.flush()
    return n


# --------------------------------------------------------------------------- retrieval


@dataclass
class Evidence:
    citation_id: str
    kind: str  # structured | retrieved
    source_type: str
    title: str
    url: Optional[str]
    text: str
    score: float
    retrieval: List[str] = field(default_factory=list)
    trust_level: str = "authoritative"

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


async def _ensure_bm25(db: AsyncSession, org_id) -> None:
    async with _bm25_lock:
        from sqlalchemy import func

        stamp = (await db.execute(select(func.count(RagChunk.id), func.max(RagChunk.created_at)))).one()
        version = f"{stamp[0]}:{stamp[1]}"
        if _bm25.version == version:
            return
        rows = (await db.execute(
            select(RagChunk.id, RagChunk.text, RagDocument.id, RagDocument.doc_metadata, RagSource.organization_id)
            .join(RagDocument, RagChunk.document_id == RagDocument.id).join(RagSource, RagDocument.source_id == RagSource.id)
        )).all()
        _bm25.build([{"chunk_id": str(r[0]), "text": r[1], "document_id": str(r[2]), "metadata": r[3] or {},
                      "org_id": str(r[4]) if r[4] else None} for r in rows], version)


def _allowed_chunks(org_id, filters: Dict[str, Any]) -> set:
    allow = set()
    for d in _bm25.docs:
        md = d["metadata"]
        if d["org_id"] and d["org_id"] != str(org_id):
            continue  # internal knowledge is org-isolated
        if filters.get("source_type") and md.get("source_type") not in _as_list(filters["source_type"]):
            continue
        if filters.get("cwe_ids") and not set(_as_list(filters["cwe_ids"])) & set(md.get("cwe_ids", [])):
            continue
        if filters.get("vuln_ids") and not set(_as_list(filters["vuln_ids"])) & set(md.get("vuln_ids", [])):
            continue
        allow.add(d["chunk_id"])
    return allow


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


async def retrieve(db: AsyncSession, query: str, *, org_id=None, filters: Optional[Dict[str, Any]] = None, top_k: int = settings.RAG_TOP_K,
                   exact_ids: Optional[List[str]] = None, use_dense: bool = True, use_keyword: bool = True) -> Dict[str, Any]:
    filters = {k: v for k, v in (filters or {}).items() if v}
    evidence: List[Evidence] = []
    diagnostics: Dict[str, Any] = {"dense": "disabled" if not use_dense else None, "keyword": "disabled" if not use_keyword else None}

    # 1. exact structured matches (authoritative)
    for vid in exact_ids or []:
        rec = (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.vuln_id == vid))).scalar_one_or_none()
        if rec:
            evidence.append(Evidence("", "structured", "vuln_intel", f"{rec.vuln_id} (structured record)",
                                     (rec.sources or {}).get("nvd", {}).get("url") or (rec.sources or {}).get("osv", {}).get("url"),
                                     vuln_record_text(rec), 1.0, ["exact_id_match"]))

    await _ensure_bm25(db, org_id)
    allow = _allowed_chunks(org_id, filters)
    fused: Dict[str, Dict[str, Any]] = {}

    def _fuse(results, label):
        for rank, r in enumerate(results):
            if r["chunk_id"] not in allow:
                continue
            e = fused.setdefault(r["chunk_id"], {"rrf": 0.0, "via": []})
            e["rrf"] += 1.0 / (60 + rank)
            e["via"].append(label)

    if use_keyword:
        kw = _bm25.search(query, top_k * 4, allow)
        diagnostics["keyword"] = len(kw)
        _fuse(kw, "bm25")
    if use_dense:
        qv = await embedder.embed([query], "query")
        if qv:
            try:
                qfilters = {k: v for k, v in filters.items() if k in ("source_type", "cwe_ids", "vuln_ids")}
                dense = await asyncio.to_thread(store.search, qv[0], top_k * 4, qfilters)
                diagnostics["dense"] = len(dense)
                _fuse(dense, "dense")
            except Exception as e:  # noqa: BLE001
                diagnostics["dense"] = f"error: {e}"[:200]
        else:
            diagnostics["dense"] = f"unavailable: {embedder.last_error or 'embeddings disabled'}"

    if fused:
        ids = [uuid.UUID(cid) for cid in sorted(fused, key=lambda k: -fused[k]["rrf"])[: top_k * 3]]
        rows = {str(r[0].id): r for r in (await db.execute(
            select(RagChunk, RagDocument, RagSource).join(RagDocument, RagChunk.document_id == RagDocument.id)
            .join(RagSource, RagDocument.source_id == RagSource.id).where(RagChunk.id.in_(ids))
        )).all()}
        qtok = set(tokenize(query))
        ident = {i.lower() for i in re.findall(r"(?:CVE-\d{4}-\d+|GHSA-[\w-]+|CWE-\d+)", query, re.I)}
        cands = []
        for cid, meta in fused.items():
            if cid not in rows:
                continue
            ch, doc, src = rows[cid]
            overlap = len(qtok & set(tokenize(ch.text))) / max(1, len(qtok))
            boost = 0.02 if any(i in ch.text.lower() for i in ident) else 0.0
            score = meta["rrf"] + 0.01 * overlap + boost  # heuristic rerank (lexical overlap + identifier match)
            cands.append(Evidence("", "retrieved", src.source_type, doc.title or src.name, doc.url, ch.text[:1800], round(score, 5),
                                  meta["via"], src.trust_level))
        cands.sort(key=lambda e: -e.score)
        seen_docs: Dict[str, int] = {}
        for e in cands:
            if seen_docs.get(e.title, 0) >= 2:
                continue
            seen_docs[e.title] = seen_docs.get(e.title, 0) + 1
            evidence.append(e)
            if len([x for x in evidence if x.kind == "retrieved"]) >= top_k:
                break

    for i, e in enumerate(evidence, 1):
        e.citation_id = f"S{i}"
    return {"query": query, "filters": filters, "evidence": [e.to_dict() for e in evidence], "diagnostics": diagnostics}


async def stats(db: AsyncSession) -> Dict[str, Any]:
    from sqlalchemy import func

    docs = (await db.execute(select(func.count(RagDocument.id)))).scalar()
    embedded = (await db.execute(select(func.count(RagDocument.id)).where(RagDocument.embedded.is_(True)))).scalar()
    chunks = (await db.execute(select(func.count(RagChunk.id)))).scalar()
    try:
        vectors = await asyncio.to_thread(store.count)
        vstatus = "ok"
    except Exception as e:  # noqa: BLE001
        vectors, vstatus = 0, f"error: {e}"[:200]
    return {"documents": docs, "embedded_documents": embedded, "chunks": chunks, "vectors": vectors, "vector_store": store.mode,
            "vector_status": vstatus, "embedding_model": settings.EMBEDDING_MODEL, "embedding_error": embedder.last_error}


def format_evidence_for_prompt(evidence: List[Dict[str, Any]], max_chars: int = 9000) -> str:
    """Quote evidence as untrusted data blocks with citation ids."""
    out, used = [], 0
    for e in evidence:
        block = f'<evidence id="{e["citation_id"]}" source="{e["source_type"]}" title="{e["title"][:120]}">\n{e["text"][:1600]}\n</evidence>'
        if used + len(block) > max_chars:
            break
        out.append(block)
        used += len(block)
    return "\n".join(out) or "<evidence>none retrieved</evidence>"
