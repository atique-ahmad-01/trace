"""
End-to-end workflow: connect repository -> scan (real scanners) -> findings -> AI investigation
blocked until a model provider is configured -> configure it via the Integrations API -> AI
investigation (LangGraph) -> remediation proposal -> human approval -> verification (real patch + re-scan).

The configured provider is swapped for `ScriptedTestProvider`, an explicitly labeled TEST DOUBLE, so
the workflow is deterministic and does not depend on a local model. Vulnerability intelligence
lookups are stubbed (marked source status "test_stub") to keep the test hermetic; scanners,
snapshots, patching and verification are real.
"""

import json
import uuid

import pytest
from sqlalchemy import select

from app.core import database
from app.db.models import AgentEvent, AgentInvestigation, Finding, RemediationProposal, VerificationRun, VulnerabilityRecord
from app.integrations import registry
from app.llm.provider import BaseProvider, LLMResult

from .conftest import register

pytestmark = pytest.mark.asyncio


class ScriptedTestProvider(BaseProvider):
    """TEST DOUBLE — returns fixed, schema-valid JSON. Never used outside tests."""

    name = "test-double"

    def __init__(self):
        super().__init__("scripted-test-model")

    async def chat(self, messages, *, json_mode=False, temperature=None, max_tokens=None):
        system = messages[0]["content"]
        if "vulnerability research" in system:
            data = {"summary": "PyYAML 5.3 FullLoader allows arbitrary code execution; fixed in 5.4 [S1].", "affected_versions": "< 5.4",
                    "exploitation_assessment": "Exploitable when untrusted YAML is loaded.", "claims": [{"text": "Fixed in 5.4", "citations": ["S1"]}], "unknowns": []}
        elif "code analysis" in system:
            data = {"attack_path": "POST /config passes request body to yaml.load", "data_flow": "request.data -> yaml.load", "reachable": "yes",
                    "exposure": "internet-facing Flask route", "confirmed": ["yaml imported in src/app.py"], "hypotheses": ["FullLoader default"], "affected_components": ["src/app.py"]}
        elif "risk assessment" in system:
            data = {"business_impact": "Remote code execution on the API host", "rationale": "Critical CVSS and reachable", "why_now": "Directly reachable", "claims": []}
        else:
            data = {"root_cause": "Outdated PyYAML with unsafe loader", "fix_summary": "Upgrade PyYAML to 5.4", "steps": ["Upgrade"], "side_effects": "None expected",
                    "confidence": "high", "patched_code": None, "claims": []}
        return LLMResult(text=json.dumps(data), model=self.model, provider=self.name, tokens_in=100, tokens_out=50, latency_ms=1)

    async def health(self):
        return {"provider": self.name, "status": "ok"}


async def _stub_lookup(db, vuln_id, aliases=None, refresh=False):
    rec = (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.vuln_id == vuln_id))).scalar_one_or_none()
    if not rec:
        rec = VulnerabilityRecord(vuln_id=vuln_id, aliases=aliases or [], summary="test stub", cvss_score=9.8, cvss_severity="CRITICAL",
                                  fixed_versions=["5.4"], affected=[{"package": "pyyaml", "fixed": ["5.4"]}], is_known_exploited=None,
                                  references=[], exploit_references=[], sources={"test_stub": {"status": "ok"}})
        db.add(rec)
        await db.flush()
    return rec


async def test_full_workflow(client, scanners_available, monkeypatch):
    from app.agents import service as agent_service
    from app.intel import service as intel
    from app.services.remediation_service import run_verification
    from app.services.scan_service import run_scan

    monkeypatch.setattr(intel, "lookup", _stub_lookup)
    monkeypatch.setattr(registry, "build_provider", lambda *a, **k: ScriptedTestProvider())

    h = await register(client, "e2e")
    repo = (await client.post("/api/v1/repositories", headers=h, json={"provider": "local", "local_path": "vulnerable-app"})).json()

    # 1. scan
    scan = (await client.post("/api/v1/scans", headers=h, json={"repository_id": repo["id"]})).json()
    await run_scan(scan["id"])
    s = (await client.get(f"/api/v1/scans/{scan['id']}", headers=h)).json()
    assert s["status"] == "COMPLETED", s["log"]
    assert {e["scanner_name"]: e["status"] for e in s["executions"]} == {"trivy": "completed", "osv-scanner": "completed", "semgrep": "completed", "gitleaks": "completed"}
    assert s["total_findings"] > 20

    # 2. normalized + deduplicated findings
    fl = (await client.get("/api/v1/findings?q=CVE-2020-14343", headers=h)).json()
    assert fl["total"] == 1
    target = fl["items"][0]
    assert target["detected_by"] == ["osv-scanner", "trivy"] and target["severity"] == "CRITICAL"
    secrets = (await client.get("/api/v1/findings?finding_type=secret", headers=h)).json()
    assert secrets["total"] == 1, "fake deploy key in src/settings_dev.py"
    assert "gitleaks" in secrets["items"][0]["detected_by"] and secrets["items"][0]["file_path"] == "src/settings_dev.py"
    assert (await client.get("/api/v1/findings?finding_type=sast", headers=h)).json()["total"] >= 5

    # 3. investigation is gated until the org configures a model provider in Settings -> Integrations
    r = await client.post(f"/api/v1/findings/{target['id']}/investigate", headers=h, json={"mode": "agentic_rag"})
    assert r.status_code == 409 and r.json()["detail"]["integration"] == "model_provider"
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "scripted-test-model"}})
    assert r.status_code == 200 and r.json()["ready"], r.text

    # 4. investigation (LangGraph)
    inv = (await client.post(f"/api/v1/findings/{target['id']}/investigate", headers=h, json={"mode": "agentic_rag"})).json()
    await agent_service.run_investigation(inv["id"])
    d = (await client.get(f"/api/v1/agents/investigations/{inv['id']}", headers=h)).json()
    assert d["status"] == "completed", d["error_message"]
    agents = {e["agent_name"] for e in d["events"]}
    assert {"supervisor", "vulnerability_research", "code_analysis", "risk_assessment", "remediation"} <= agents
    assert d["research"]["facts"]["cvss_score"] == 9.8, "facts come from structured intel, not the model"
    assert d["code_analysis"]["static_reachability"] is True, "yaml is imported in src/app.py"
    assert d["risk_assessment"]["priority"] == "P1"
    assert any(t["invoked_by"] == "agent:code_analysis" and t["status"] == "success" for t in d["tool_executions"]), "MCP search_code executed"

    # 5. remediation proposal with a real manifest patch
    props = (await client.get("/api/v1/remediation/proposals", headers=h)).json()["items"]
    assert len(props) == 1
    p = (await client.get(f"/api/v1/remediation/proposals/{props[0]['id']}", headers=h)).json()
    assert p["remediation_type"] == "dependency_upgrade" and p["files_changed"] == ["requirements.txt"]
    assert "+pyyaml==5.4" in p["patch"].lower()

    # verification is blocked before approval
    assert (await client.post(f"/api/v1/remediation/proposals/{p['id']}/verify", headers=h)).status_code == 409
    r = await client.post(f"/api/v1/remediation/proposals/{p['id']}/decision", headers=h, json={"decision": "approved", "comment": "LGTM"})
    assert r.status_code == 200 and r.json()["status"] == "approved"

    # 6. verification: apply patch to a fresh snapshot, re-scan before/after
    vr = (await client.post(f"/api/v1/remediation/proposals/{p['id']}/verify", headers=h)).json()
    await run_verification(vr["id"])
    p2 = (await client.get(f"/api/v1/remediation/proposals/{p['id']}", headers=h)).json()
    v = p2["verifications"][0]
    assert v["patch_applied"] is True
    assert v["target_finding_present_before"] is True and v["target_finding_present_after"] is False, v["details"]
    assert v["status"] == "passed", v["details"]
    assert p2["status"] == "verified"

    # 7. audit trail
    actions = [a["action"] for a in (await client.get("/api/v1/organizations/current/audit?page_size=100", headers=h)).json()["items"]]
    for a in ("repository.connect", "scan.trigger", "integration.save", "investigation.start", "remediation.approved", "remediation.verify"):
        assert a in actions
