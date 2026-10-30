"""
Common finding schema, severity mapping and fingerprinting/deduplication.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedFinding:
    scanner: str
    finding_type: str  # dependency | sast | secret | misconfig
    title: str
    severity: str
    description: str = ""
    rule_id: Optional[str] = None
    vuln_id: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    package_name: Optional[str] = None
    package_ecosystem: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    detected_by: List[str] = field(default_factory=list)

    def canonical_vuln_id(self) -> Optional[str]:
        ids = [self.vuln_id, *self.aliases]
        for i in ids:
            if i and i.upper().startswith("CVE-"):
                return i.upper()
        return self.vuln_id

    def fingerprint(self) -> str:
        if self.finding_type == "dependency":
            parts = ["dep", self.canonical_vuln_id() or "", (self.package_name or "").lower(), self.file_path or ""]
        elif self.finding_type == "secret":
            # rule ids differ between secret scanners; location identifies the secret
            parts = ["secret", self.file_path or "", str(self.start_line or "")]
        else:
            parts = [self.finding_type, self.rule_id or self.title, self.file_path or "", str(self.start_line or "")]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def norm_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    v = str(value).strip().upper()
    mapping = {"MODERATE": "MEDIUM", "ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW", "INFO": "INFO", "NEGLIGIBLE": "LOW"}
    v = mapping.get(v, v)
    if v in SEVERITIES:
        return v
    try:
        return severity_from_cvss(float(v))
    except ValueError:
        return "UNKNOWN"


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


_CWE_RE = re.compile(r"CWE-\d+", re.I)


def extract_cwes(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        values = [values]
    out: List[str] = []
    for v in values:
        out.extend(m.upper() for m in _CWE_RE.findall(str(v)))
    return sorted(set(out))


def dedupe(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """Merge findings with the same fingerprint, keeping the richest record and all detecting scanners."""
    merged: Dict[str, NormalizedFinding] = {}
    for f in findings:
        if f.finding_type == "dependency":
            cid = f.canonical_vuln_id()
            if cid and cid != f.vuln_id:
                if f.vuln_id:
                    f.aliases = sorted(set(f.aliases) | {f.vuln_id})
                f.vuln_id = cid
        key = f.fingerprint()
        f.detected_by = sorted(set(f.detected_by) | {f.scanner})
        if key not in merged:
            merged[key] = f
            continue
        cur = merged[key]
        cur.detected_by = sorted(set(cur.detected_by) | set(f.detected_by))
        cur.aliases = sorted(set(cur.aliases) | set(f.aliases))
        cur.references = list(dict.fromkeys(cur.references + f.references))[:30]
        cur.cwe_ids = sorted(set(cur.cwe_ids) | set(f.cwe_ids))
        if SEVERITIES.index(f.severity) < SEVERITIES.index(cur.severity):
            cur.severity = f.severity
        for attr in ("cvss_score", "fixed_version", "description", "installed_version", "start_line", "code_snippet"):
            if not getattr(cur, attr) and getattr(f, attr):
                setattr(cur, attr, getattr(f, attr))
    return list(merged.values())
