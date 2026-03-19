"""Hafif duman testleri — CI ve yerel hızlı doğrulama (harici DFIR binary gerekmez)."""

from __future__ import annotations


def test_import_core_reporter_constants() -> None:
    from core.reporter import DEFAULT_CASE_TITLE, DEFAULT_INCIDENT_RESPONSE_TITLE

    assert "Dijital" in DEFAULT_INCIDENT_RESPONSE_TITLE
    assert "DİZ" in DEFAULT_CASE_TITLE or "DIZ" in DEFAULT_CASE_TITLE.upper()


def test_artifact_manifest_fingerprint_empty() -> None:
    from core.reporter import artifact_manifest_fingerprint_sha256

    out = artifact_manifest_fingerprint_sha256([])
    assert isinstance(out, str)
    assert len(out) > 5


def test_intervention_playbook_baseline_without_findings() -> None:
    from core.ai_analyst import generate_intervention_playbook

    pb = generate_intervention_playbook([], None)
    steps = pb.get("steps") or []
    # Boş bulguda bile ağ/ bulut artefaktı varsa somut adımlar üretilebilir; en az bir playbook adımı olmalı.
    assert len(steps) >= 1


def test_version_in_pyproject() -> None:
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', text)
    assert m, "pyproject.toml içinde [project] version bulunamadı"
    parts = m.group(1).split(".")
    assert len(parts) >= 2
