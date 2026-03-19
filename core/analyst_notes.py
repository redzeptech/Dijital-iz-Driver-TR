"""
Analist Not Defteri — Timesketch tarzı işbirlikli triyaj.

Bulgulara false positive / kritik emare etiketi ve serbest metin notu eklenir;
``data/results/analyst_notebook.json`` içinde saklanır ve HTML raporda «Uzman Görüşü» bölümüne aktarılır.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
NOTEBOOK_PATH = ROOT / "data" / "results" / "analyst_notebook.json"

CLASSIFICATION_LABELS_TR: dict[str, str] = {
    "false_positive": "Bu bir False Positive (uzman triyajı)",
    "critical_indicator": "Bu kritik bir sızma emaresi",
    "analyst_note": "Analist notu",
}


def _ensure_results_dir() -> None:
    NOTEBOOK_PATH.parent.mkdir(parents=True, exist_ok=True)


def fingerprint_finding(event: dict[str, Any], *, mask_sensitive: bool = False) -> str:
    """
    Bulgu için stabil parmak izi (raporda KVKK maskesi ile aynı kurallar mask_sensitive=True iken).
    """
    try:
        from core.masking import mask_data
    except ImportError:
        def mask_data(s: str, **_k: Any) -> str:  # type: ignore[misc]
            return s

    ts_val = event.get("Timestamp", "")
    if hasattr(ts_val, "strftime"):
        ts = ts_val.strftime("%Y-%m-%d %H:%M:%S")[:19]
    else:
        ts = str(ts_val)[:19]
    src = str(event.get("Source", "")).strip()
    rt = str(event.get("RuleTitle", ""))[:240]
    dt = str(event.get("Details", ""))[:500]
    if mask_sensitive:
        rt = mask_data(rt)
        dt = mask_data(dt)
    payload = f"{ts}|{src}|{rt}|{dt}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_notebook() -> dict[str, Any]:
    if not NOTEBOOK_PATH.exists():
        return {"version": 1, "notes": []}
    try:
        data = json.loads(NOTEBOOK_PATH.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(data, dict):
            return {"version": 1, "notes": []}
        notes = data.get("notes")
        if not isinstance(notes, list):
            data["notes"] = []
        data.setdefault("version", 1)
        return data
    except (json.JSONDecodeError, OSError):
        return {"version": 1, "notes": []}


def save_notebook(data: dict[str, Any]) -> None:
    _ensure_results_dir()
    data.setdefault("version", 1)
    notes = data.get("notes")
    if not isinstance(notes, list):
        data["notes"] = []
    NOTEBOOK_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def append_analyst_note(
    finding: dict[str, Any],
    classification: str,
    *,
    analyst_comment: str = "",
    analyst_name: str = "",
    mask_sensitive: bool = False,
) -> dict[str, Any]:
    """
    Yeni not ekler. ``classification``: false_positive | critical_indicator | analyst_note
    """
    if classification not in CLASSIFICATION_LABELS_TR:
        classification = "analyst_note"
    data = load_notebook()
    notes: list[dict[str, Any]] = list(data.get("notes") or [])
    fp = fingerprint_finding(finding, mask_sensitive=mask_sensitive)
    ts_raw = finding.get("Timestamp", "")
    ts_disp = ts_raw.strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_raw, "strftime") else str(ts_raw)[:19]
    note = {
        "fingerprint": fp,
        "classification": classification,
        "label_tr": CLASSIFICATION_LABELS_TR.get(classification, classification),
        "analyst_comment": (analyst_comment or "").strip(),
        "analyst_name": (analyst_name or "").strip() or "Analist",
        "finding_snapshot": {
            "Timestamp": ts_disp,
            "Source": str(finding.get("Source", "")),
            "RuleTitle": str(finding.get("RuleTitle", ""))[:300],
            "Details": str(finding.get("Details", ""))[:500],
        },
        "mask_sensitive_at_save": bool(mask_sensitive),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    notes.append(note)
    data["notes"] = notes
    save_notebook(data)
    return note


def delete_note_at_index(index: int) -> bool:
    data = load_notebook()
    notes = list(data.get("notes") or [])
    if 0 <= index < len(notes):
        notes.pop(index)
        data["notes"] = notes
        save_notebook(data)
        return True
    return False


def get_expert_opinions_for_report(mask_sensitive: bool = True) -> list[dict[str, Any]]:
    """HTML şablonu için «Uzman Görüşü» satırları (sıralı, maskeleme isteğe bağlı)."""
    try:
        from core.masking import mask_data
    except ImportError:
        def mask_data(s: str, **_k: Any) -> str:  # type: ignore[misc]
            return str(s)

    data = load_notebook()
    notes_raw = [n for n in (data.get("notes") or []) if isinstance(n, dict)]
    out: list[dict[str, Any]] = []
    for n in notes_raw:
        snap = dict(n.get("finding_snapshot") or {})
        comment = str(n.get("analyst_comment", ""))
        name = str(n.get("analyst_name", ""))
        if mask_sensitive:
            snap = {k: mask_data(str(v)) for k, v in snap.items()}
            comment = mask_data(comment)
            name = mask_data(name) if name else name
        badge = "fp" if n.get("classification") == "false_positive" else "crit" if n.get("classification") == "critical_indicator" else "note"
        out.append(
            {
                "classification": n.get("classification", "analyst_note"),
                "label_tr": n.get("label_tr", ""),
                "badge_class": badge,
                "analyst_comment": comment,
                "analyst_name": name,
                "finding_snapshot": snap,
                "created_at": n.get("created_at", ""),
            }
        )
    out.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
    return out

