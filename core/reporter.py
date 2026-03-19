"""
Dijital İz Sürücü - Rapor Modülü
Jinja2 ile profesyonel vaka raporu (HTML/PDF), KVKK maskeleme.

Tasarım hedefi: Magnet AXIOM / Oxygen Forensics rapor disiplini —
üst bölümde kritik çoklu korelasyon, interaktif zaman çizelgesi ve saldırı görünümü.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .correlator import _load_cloud_findings_disk, _load_mobile_findings_disk
from .utils import _flatten_vol_tree

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "results"
TEMPLATE_DIR = ROOT / "templates"

DEFAULT_CASE_TITLE = "DİZ Vaka Analiz Raporu #001"
# Otomatik olay müdahalesi / CLI `--report --pdf` çıktısı için varsayılan kapak başlığı
DEFAULT_INCIDENT_RESPONSE_TITLE = "Dijital İz Sürücü - Otomatik Olay Müdahale Analizi"

IP_V4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
SUSPICIOUS_EXT = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".sys")
_FORE_PATH_TOKEN = re.compile(
    r"[\w\-.\s\\/:]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|msi|scr|sys|pdf|docx?|xlsx?)\b",
    re.I,
)


def _extract_forensic_tokens(text: str) -> set[str]:
    if not text:
        return set()
    out: set[str] = set()
    for m in _FORE_PATH_TOKEN.finditer(text):
        frag = m.group(0).strip().lower()
        if len(frag) < 4:
            continue
        base = Path(frag.replace("\\", "/")).name
        if base:
            out.add(base)
        out.add(frag[-120:])
    return out


def _disk_ram_collision_row_indices(events: list[dict]) -> set[int]:
    """Aynı dosya/süreç adı hem Disk (EVTX) hem RAM (Volatility) olaylarında geçiyorsa satır indeksleri."""
    ram_tokens: set[str] = set()
    disk_tokens: set[str] = set()
    for e in events:
        if not isinstance(e, dict):
            continue
        src = str(e.get("Source", "") or "")
        blob = f"{e.get('RuleTitle', '')} {e.get('Details', '')}"
        toks = _extract_forensic_tokens(blob)
        if not toks:
            continue
        if src == "Volatility":
            ram_tokens |= toks
        if src in ("Hayabusa", "Chainsaw"):
            disk_tokens |= toks
    shared = ram_tokens & disk_tokens
    if not shared:
        return set()
    hit: set[int] = set()
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            continue
        src = str(e.get("Source", "") or "")
        if src not in ("Volatility", "Hayabusa", "Chainsaw"):
            continue
        blob = f"{e.get('RuleTitle', '')} {e.get('Details', '')}"
        toks = _extract_forensic_tokens(blob)
        if toks & shared:
            hit.add(i)
    return hit


def _annotate_disk_ram_collision(events: list[dict], prepared: list[dict]) -> None:
    """Kritik çakışma: motor onayı (confirmed_threat) veya çift kaynak dosya eşleşmesi."""
    idx_hit = _disk_ram_collision_row_indices(events)
    for i, row in enumerate(prepared):
        row["disk_ram_collision"] = bool(row.get("confirmed_threat")) or (i in idx_hit)


def load_section_analyst_notes(mask_sensitive: bool) -> dict[str, str]:
    """
    Bölüm altı 'Adli özet — Analist notu'.
    ``report_section_notes.json`` örnek: {"storyline": "...", "mitre": "..."}
    """
    from .masking import mask_data

    p = RESULTS / "report_section_notes.json"
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        txt = v.strip()
        if mask_sensitive:
            txt = mask_data(txt)
        out[k] = txt
    return out


def collect_results_artifact_hashes(
    results_dir: Path | None = None,
    max_file_bytes: int = 120 * 1024 * 1024,
    max_files: int = 900,
) -> list[dict[str, Any]]:
    """
    Ham sonuç dosyaları (JSON/CSV) SHA-256 — Kanıt Doğrulama Tablosu.
    """
    base = Path(results_dir) if results_dir is not None else RESULTS
    if not base.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for p in sorted(base.rglob("*")):
        if len(rows) >= max_files:
            break
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".json", ".csv"):
            continue
        try:
            rel = p.relative_to(base).as_posix()
        except ValueError:
            rel = p.name
        if "/." in rel or rel.startswith("."):
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz > max_file_bytes:
            rows.append(
                {
                    "rel_path": rel,
                    "sha256": "— (özet atlandı: boyut limiti)",
                    "size_bytes": sz,
                }
            )
            continue
        try:
            digest = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            rows.append({"rel_path": rel, "sha256": digest.hexdigest(), "size_bytes": sz})
        except OSError:
            continue
    rows.sort(key=lambda r: str(r.get("rel_path", "")))
    return rows


def artifact_manifest_fingerprint_sha256(artifact_hash_rows: list[dict[str, Any]]) -> str:
    """
    Ham kanıt dosyaları (tablodaki geçerli SHA-256 satırları) için tek bir manifest özeti.
    Kapakta 'doğrulama özeti' olarak gösterilir; satır bazlı tablo rapor gövdesindedir.
    """
    lines: list[str] = []
    for r in artifact_hash_rows:
        sha = str(r.get("sha256", "") or "").strip().lower()
        rel = str(r.get("rel_path", "") or "")
        if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
            lines.append(f"{rel}:{sha}")
    lines.sort()
    if not lines:
        return "— (hashlenmiş JSON/CSV yok — sonuç dizinini doldurun)"
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _hhmm_from_ts(ts: str) -> str:
    s = (ts or "").strip().replace("T", " ")[:19]
    if len(s) >= 16 and s[10] == " ":
        return s[11:16]
    if len(s) >= 5:
        return s[:5]
    return "—"


def _story_flow_lane_public(lane: str) -> str:
    x = (lane or "").strip().lower()
    if "mobil" in x:
        return "Mobil"
    if "bulut" in x or "cloud" in x:
        return "Bulut"
    if "ağ" in x or "network" in x or x == "zeek":
        return "Ağ"
    if "ram" in x or "bellek" in x or "volatility" in x or "süreç" in x:
        return "RAM"
    if "disk" in x or "evtx" in x:
        return "Disk"
    return (lane or "Olay")[:24]


def build_narrative_story_flow_lines(vertical_timeline_rows: list[dict[str, Any]]) -> list[str]:
    """Örn.: [09:15 - Disk] PDF açıldığında PowerShell script tetiklendi."""
    lines: list[str] = []
    for row in vertical_timeline_rows:
        hhmm = _hhmm_from_ts(str(row.get("time", "")))
        lane = _story_flow_lane_public(str(row.get("lane", "")))
        title = str(row.get("title", "")).strip()
        detail = str(row.get("detail", "")).strip()
        body = title
        if detail and detail.lower() not in title.lower():
            body = f"{title} ({detail})" if title else detail
        if not body:
            body = "(olay özeti yok)"
        lines.append(f"[{hhmm} - {lane}] {body}")
    return lines


def _load_json_file(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _is_private_ip(ip: str) -> bool:
    ip = ip.strip()
    m = IP_V4.fullmatch(ip)
    if not m:
        return True
    o = [int(x) for x in ip.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 127:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    return False


def _is_plausible_ip(ip: str) -> bool:
    if not ip or "*" in ip or "xxx" in ip.lower():
        return False
    if not IP_V4.fullmatch(ip.strip()):
        return False
    return not _is_private_ip(ip.strip())


def _collect_ips_from_network(net: dict | list | None, priority_lists: tuple[str, ...]) -> dict[str, str]:
    ip_labels: dict[str, str] = {}
    if not isinstance(net, dict):
        return ip_labels
    for key in priority_lists:
        items = net.get(key) or []
        if not isinstance(items, list):
            continue
        label = {
            "beaconing_suspicious": "Beaconing",
            "dns_tunneling_suspicious": "DNS tünelleme",
            "connections": "Bağlantı",
            "http_traffic": "HTTP",
        }.get(key, key)
        for item in items:
            if not isinstance(item, (dict, list, str)):
                continue
            blob = json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item
            for m in IP_V4.finditer(blob):
                val = m.group(0)
                if _is_plausible_ip(val) and val not in ip_labels:
                    ip_labels[val] = label
    return ip_labels


def _ips_from_volatility_netscan() -> dict[str, str]:
    out: dict[str, str] = {}
    path = RESULTS / "volatility" / "windows_netscan.json"
    data = _load_json_file(path)
    if isinstance(data, dict) and "__children" in data:
        rows = _flatten_vol_tree(data)
    elif isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    else:
        rows = []
    for r in rows:
        ra = str(r.get("RemoteAddress") or r.get("remote_address") or "")
        for m in IP_V4.finditer(ra):
            val = m.group(0)
            if _is_plausible_ip(val):
                out.setdefault(val, "Volatility netscan")
    return out


def _relationship_pick_hub_ip(net: dict[str, Any], mask_sensitive: bool) -> str | None:
    if mask_sensitive:
        sample = json.dumps(net, ensure_ascii=False)[:2000]
        if "*" in sample or "xxx" in sample.lower():
            return None
    if not isinstance(net, dict):
        return None
    bucket: dict[str, str] = {}
    bucket.update(
        _collect_ips_from_network(
            net,
            ("beaconing_suspicious", "dns_tunneling_suspicious", "connections", "http_traffic"),
        )
    )
    bucket.update(_ips_from_volatility_netscan())
    if not bucket:
        return None
    for pref in ("beaconing_suspicious", "dns_tunneling_suspicious"):
        for item in net.get(pref) or []:
            if not isinstance(item, dict):
                continue
            for m in IP_V4.finditer(json.dumps(item, ensure_ascii=False)):
                val = m.group(0)
                if _is_plausible_ip(val) and val in bucket:
                    return val
    return sorted(bucket.keys())[0]


def _relationship_pick_hub_user(cloud: dict[str, Any]) -> str | None:
    for bucket in ("bulut_sizintisi", "hybrid_attacks", "critical_events"):
        for e in cloud.get(bucket) or []:
            if not isinstance(e, dict):
                continue
            u = e.get("User_Identity") or e.get("user_arn") or e.get("privilege_summary")
            if isinstance(u, str) and len(u.strip()) > 4:
                return u.strip()[:120]
    return None


def collect_suspicious_file_paths_for_report() -> list[str]:
    paths: list[str] = []
    net = _load_json_file(RESULTS / "network_analysis.json")
    if isinstance(net, dict):
        for sf in net.get("suspicious_files", []) or []:
            if isinstance(sf, dict):
                p = sf.get("extracted_path") or sf.get("filename") or sf.get("name") or ""
                if p:
                    paths.append(str(p))
    for name in ("windows_malfind.json", "windows_pslist.json", "windows_filescan.json"):
        raw = _load_json_file(RESULTS / "volatility" / name)
        for row in _flatten_vol_tree(raw):
            if not isinstance(row, dict):
                continue
            for key in ("Process", "process", "ImageFileName", "Image", "Name", "MappedPath", "Path"):
                v = row.get(key)
                if isinstance(v, str) and (":" in v or "\\" in v or "/" in v):
                    if any(v.lower().endswith(ext) for ext in SUSPICIOUS_EXT) or "malfind" in name.lower():
                        paths.append(v[:500])
                        break
    for kr in (RESULTS / "kape", RESULTS / "kape_output", RESULTS / "KAPE"):
        if kr.is_dir():
            for p in kr.rglob("*"):
                if p.is_file() and p.suffix.lower() in SUSPICIOUS_EXT:
                    paths.append(str(p))
                    if len(paths) > 200:
                        break
        if len(paths) > 200:
            break
    seen: set[str] = set()
    uniq: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:24]


def load_analyst_storyline_narrative(mask_sensitive: bool, override: str | None = None) -> str:
    """
    AI analist özeti: parametre > detective_report.md / attack_scenario.md ilk bölüm.
    """
    from .masking import mask_data

    if override and override.strip():
        text = override.strip()
        return mask_data(text) if mask_sensitive else text

    for name in ("detective_report.md", "attack_scenario.md"):
        p = RESULTS / name
        if not p.exists():
            continue
        raw = p.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            continue
        paras = [x.strip() for x in re.split(r"\n{2,}", raw) if x.strip()]
        text = paras[0] if paras else raw[:2000]
        if len(text) > 2800:
            text = text[:2800].rsplit(" ", 1)[0] + "…"
        return mask_data(text) if mask_sensitive else text

    return (
        "Otomatik AI analist özeti henüz üretilmedi veya markdown bulunamadı. "
        "`main.py --diz-ai` / `--ai-detective` ile `attack_scenario.md` veya `detective_report.md` oluşturun; "
        "veya `generate_html_report(..., analyst_storyline=\"...\")` ile giriş paragrafı sağlayın."
    )


def narrative_paragraphs_to_html(text: str) -> str:
    """Kaçışlı HTML paragrafları — Storyline girişi."""
    parts = [p.strip() for p in text.replace("\r", "").split("\n\n") if p.strip()]
    if not parts:
        parts = [text.strip()] if text.strip() else []
    if not parts:
        return '<p class="story-p">—</p>'
    return "".join(f'<p class="story-p">{html.escape(p)}</p>' for p in parts[:8])


def compute_kill_chain_three_stage(
    events: list[dict],
    exfil_threats: list[Any],
    confirmed_threats: list[Any],
    ato_threats: list[Any],
    fs_threats: list[Any],
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> dict[str, Any]:
    """
    PDF / Storyline için 3 safha: Keşif → Sızma → Sızıntı.
    Sinyal mantığı `ui/app.compute_kill_chain_status` ile hizalı; burada üst seviye özet.
    """
    net = _load_json_file(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}

    parts: list[str] = []
    for e in events[:2500]:
        if not isinstance(e, dict):
            continue
        parts.append(str(e.get("RuleTitle", "") or e.get("rule_title", "")))
        parts.append(str(e.get("Details", "") or e.get("details", "")))
    blob = " ".join(parts).lower()

    recon = bool(net.get("dns_tunneling_suspicious"))
    if not recon:
        for kw in (
            "scan",
            "enumerate",
            "recon",
            "whoami",
            "net user",
            "net group",
            "kerberoast",
            "ldap",
            "discovery",
            "port scan",
        ):
            if kw in blob:
                recon = True
                break

    initial = bool(fs_threats)
    if not initial:
        for e in events:
            if not isinstance(e, dict):
                continue
            lv = str(e.get("Level", "") or e.get("level", "")).lower()
            if lv in ("critical", "high", "crit", "yüksek"):
                initial = True
                break
        if not initial and (mobile_payload.get("whatsapp_messages") or mobile_payload.get("sms_messages")):
            initial = True
        if not initial and blob:
            for kw in ("malfind", "malware", "powershell -enc", "downloadstring", "wscript", "mshta", "cmd.exe /c"):
                if kw in blob:
                    initial = True
                    break

    priv = bool(confirmed_threats)
    if not priv:
        for kw in (
            "privilege",
            "elevation",
            "uac bypass",
            "token",
            "administrator",
            "sebackup",
            "lsass",
            "mimikatz",
            "process injection",
        ):
            if kw in blob:
                priv = True
                break
    if not priv:
        for bucket in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
            for ev in cloud_payload.get(bucket) or []:
                if not isinstance(ev, dict):
                    continue
                act = str(ev.get("Action") or ev.get("event_name") or "").lower()
                if any(
                    x in act
                    for x in (
                        "attachuserpolicy",
                        "attachrolepolicy",
                        "createloginprofile",
                        "createaccesskey",
                        "assumerole",
                        "roleassignment",
                    )
                ):
                    priv = True
                    break
            if priv:
                break

    lateral = bool(ato_threats)
    if not lateral:
        for kw in (
            "lateral",
            "remote desktop",
            "rdp",
            "winrm",
            "wmic",
            "dcom",
            "psexec",
            "smb",
            "pass the hash",
            "schedule task remote",
            "wmi subscription",
        ):
            if kw in blob:
                lateral = True
                break
    if not lateral:
        for conn in net.get("connections") or []:
            if not isinstance(conn, dict):
                continue
            ob = float(conn.get("orig_bytes") or 0)
            if ob >= 50_000_000:
                lateral = True
                break

    exfil = bool(exfil_threats)
    if not exfil:
        for kw in ("exfil", "sızdır", "sizint", "rclone", "mega", "archive", "compress password", "dns tunnel"):
            if kw in blob:
                exfil = True
                break
    if not exfil:
        for row in net.get("beaconing_suspicious") or []:
            if not isinstance(row, dict):
                continue
            ob = float(row.get("orig_bytes") or 0)
            if ob >= 5_000_000 or row.get("beaconing_suspicious"):
                exfil = True
                break
    if not exfil and (net.get("dns_tunneling_suspicious") or []):
        exfil = True

    stage_intrusion = bool(initial or priv or lateral or fs_threats or ato_threats or confirmed_threats)
    keşif = bool(recon)
    sızma = bool(stage_intrusion)
    sızıntı = bool(exfil)

    labels_tr = ["Keşif", "Sızma", "Sızıntı"]
    detected = [keşif, sızma, sızıntı]
    hit_ix = [i for i, d in enumerate(detected) if d]
    cur = max(hit_ix) if hit_ix else -1
    cur_lbl = labels_tr[cur] if cur >= 0 else "Henüz safha tespiti yok"

    steps: list[dict[str, Any]] = []
    for i, lbl in enumerate(labels_tr):
        steps.append(
            {
                "label": lbl,
                "done": bool(detected[i]),
                "current": cur == i,
            }
        )

    return {
        "steps": steps,
        "detected": detected,
        "current_index": cur,
        "current_label_tr": cur_lbl,
        "summary_tr": (
            f"Kill chain özeti: Keşif={'evet' if keşif else 'hayır'}, Sızma={'evet' if sızma else 'hayır'}, "
            f"Sızıntı={'evet' if sızıntı else 'hayır'}. Aktif vurgu: {cur_lbl}."
        ),
    }


def _storyline_lane_and_icon(source: str, rule_title: str) -> tuple[str, str]:
    s = (source or "").strip()
    rt = (rule_title or "").upper()
    if s == "Zeek":
        return "Ağ", "&#128260;"
    if s == "Volatility":
        if "NETWORK" in rt:
            return "RAM", "&#129504;"
        return "RAM", "&#129504;"
    if s in ("Hayabusa", "Chainsaw"):
        return "Disk", "&#128196;"
    if "cloud" in s.lower() or "CLOUD" in rt:
        return "Bulut", "&#9729;"
    return "Disk", "&#128196;"


def _parse_cloud_ts(ev: dict) -> str:
    for k in ("EventTime", "event_time", "Timestamp", "timestamp", "Time", "time"):
        v = ev.get(k)
        if v:
            return str(v)[:19].replace("T", " ")
    return ""


def build_storyline_vertical_timeline(
    prepared_events: list[dict],
    mobile_payload: dict[str, Any],
    cloud_payload: dict[str, Any],
    cross_alignment: dict[str, Any] | None,
    max_items: int = 22,
) -> list[dict[str, Any]]:
    """Mobil · Disk · RAM · Bulut · Ağ — dikey olay örgüsü (PDF için sıralı)."""
    rows: list[dict[str, Any]] = []

    for e in prepared_events:
        ts = str(e.get("timestamp", ""))[:19]
        if not _parse_ts(ts):
            continue
        lane, icon = _storyline_lane_and_icon(str(e.get("source", "")), str(e.get("rule_title", "")))
        rows.append(
            {
                "time": ts,
                "lane": lane,
                "icon": icon,
                "title": (e.get("rule_title") or "")[:100],
                "detail": (e.get("details") or "")[:160],
                "level_class": e.get("level_class", "info"),
                "_sort": _parse_ts(ts) or datetime.min,
            }
        )

    wa = mobile_payload.get("whatsapp_messages") or []
    if isinstance(wa, list) and wa:
        first_ts = ""
        for m in wa[:400]:
            if not isinstance(m, dict):
                continue
            t = str(m.get("timestamp_iso") or m.get("timestamp") or "")[:19]
            if t:
                first_ts = t.replace("T", " ")
                break
        label = f"Mobil · WhatsApp kanıtı ({len(wa)} kayıt)"
        rows.append(
            {
                "time": first_ts or "—",
                "lane": "Mobil",
                "icon": "&#128241;",
                "title": label[:100],
                "detail": "Msgstore / çoklu kaynak kümesi ile hizalı olabilir.",
                "level_class": "high",
                "_sort": _parse_ts(first_ts.replace("T", " ")[:19])
                if len(first_ts) >= 10
                else datetime.min,
            }
        )

    sms = mobile_payload.get("sms_messages") or []
    if isinstance(sms, list) and sms and not wa:
        first_ts = ""
        for m in sms[:200]:
            if isinstance(m, dict):
                t = str(m.get("timestamp_iso") or m.get("timestamp") or "")[:19]
                if t:
                    first_ts = t.replace("T", " ")
                    break
        rows.append(
            {
                "time": first_ts or "—",
                "lane": "Mobil",
                "icon": "&#128241;",
                "title": f"Mobil · SMS ({len(sms)} kayıt)",
                "detail": "Cihaz içi iletişim kanıtı.",
                "level_class": "medium",
                "_sort": _parse_ts(first_ts.replace("T", " ")[:19])
                if len(first_ts) >= 10
                else datetime.min,
            }
        )

    for bucket in ("critical_events", "hybrid_attacks", "bulut_sizintisi"):
        for ev in cloud_payload.get(bucket) or []:
            if not isinstance(ev, dict):
                continue
            ts = _parse_cloud_ts(ev)
            act = str(ev.get("Action") or ev.get("event_name") or ev.get("summary", ""))[:80]
            uid = str(ev.get("User_Identity") or ev.get("user_arn") or "")[:60]
            rows.append(
                {
                    "time": ts or "—",
                    "lane": "Bulut",
                    "icon": "&#9729;",
                    "title": act or bucket,
                    "detail": uid,
                    "level_class": "critical",
                    "_sort": _parse_ts(ts) if ts and _parse_ts(ts) else datetime.min,
                }
            )

    if cross_alignment:
        for cl in (cross_alignment.get("ranked_by_coverage") or [])[:3]:
            srcs = set(cl.get("sources_present") or [])
            tstr = str(cl.get("time_start_utc", ""))[:19].replace("T", " ")
            if "mobile" in srcs:
                rows.append(
                    {
                        "time": tstr or "—",
                        "lane": "Mobil",
                        "icon": "&#128241;",
                        "title": "Korelasyon kümesi (mobil + diğer)",
                        "detail": (cl.get("summary_short") or cl.get("note") or "")[:160],
                        "level_class": "high",
                        "_sort": _parse_ts(tstr) if tstr else datetime.min,
                    }
                )
            if "cloud" in srcs:
                rows.append(
                    {
                        "time": tstr or "—",
                        "lane": "Bulut",
                        "icon": "&#9729;",
                        "title": "Korelasyon kümesi (bulut + diğer)",
                        "detail": (cl.get("summary_short") or cl.get("note") or "")[:160],
                        "level_class": "high",
                        "_sort": _parse_ts(tstr) if tstr else datetime.min,
                    }
                )

    rows.sort(key=lambda r: r.get("_sort") or datetime.min)
    out: list[dict[str, Any]] = []
    for r in rows:
        r2 = {k: v for k, v in r.items() if k != "_sort"}
        out.append(r2)
        if len(out) >= max_items:
            break
    return out


def build_relationship_diagram_svg(
    mask_sensitive: bool,
    cloud_payload: dict[str, Any],
    file_paths: list[str],
) -> str:
    """Saldırgan / şüpheli merkez — dosya ve bulut kullanıcı uçları (SVG)."""
    from .masking import mask_data

    net = _load_json_file(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}
    hub_ip = _relationship_pick_hub_ip(net, mask_sensitive)
    hub_user = _relationship_pick_hub_user(cloud_payload) if cloud_payload else None
    hub_user_display = mask_data(hub_user) if (mask_sensitive and hub_user) else hub_user
    hub_label = hub_ip or hub_user_display
    if mask_sensitive and hub_ip:
        hub_label = mask_data(hub_ip)

    esc = lambda t: html.escape(str(t)[:70], quote=True)

    files = list(file_paths[:6])
    w, h = 520, 260
    cx, cy = 260, 130
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'role="img" aria-label="İlişki şeması — merkez uç ve dosya / kimlik" '
        'style="max-width:100%;height:auto;display:block;">',
        "<defs>",
        '<marker id="kcArr" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">',
        '<path d="M0,0 L7,3.5 L0,7 z" fill="#64748b"/>',
        "</marker>",
        "</defs>",
        '<rect x="1" y="1" width="' + str(w - 2) + '" height="' + str(h - 2) + '" rx="12" '
        'fill="#0f172a" stroke="#1e3a5f" stroke-width="1"/>',
    ]

    if not hub_label:
        parts.append(
            f'<text x="{w // 2}" y="{h // 2}" text-anchor="middle" fill="#94a3b8" font-size="13" font-family="Segoe UI,sans-serif">'
            "Şema için şüpheli dış IP (Zeek/PCAP) veya bulut kimliği gerekir.</text>"
        )
        parts.append("</svg>")
        return "\n".join(parts)

    # Merkez
    parts.append(
        f'<circle cx="{cx}" cy="{cy}" r="46" fill="#1e293b" stroke="#00bcf2" stroke-width="2"/>'
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" fill="#e2e8f0" font-size="11" font-weight="700" '
        f'font-family="Segoe UI,sans-serif">Merkez uç (şüpheli)</text>'
        f'<text x="{cx}" y="{cy + 10}" text-anchor="middle" fill="#7dd3fc" font-size="10" font-family="Consolas,monospace">'
        f"{esc(hub_label)}</text>"
    )

    # Dosyalar (sol)
    fy0 = 36
    for i, fp in enumerate(files):
        display = Path(fp).name if len(fp) > 60 else fp
        if mask_sensitive:
            display = mask_data(display)
        y = fy0 + i * 34
        x0 = 28
        x_line_end = cx - 50
        parts.append(
            f'<line x1="{cx}" y1="{cy}" x2="{x_line_end}" y2="{y}" stroke="#475569" stroke-width="1.2" marker-end="url(#kcArr)"/>'
            f'<rect x="{x0 - 12}" y="{y - 14}" width="150" height="28" rx="6" fill="#111d2e" stroke="#334155"/>'
            f'<text x="{x0}" y="{y + 4}" fill="#cbd5e1" font-size="9" font-family="Segoe UI,sans-serif">{esc(display)}</text>'
        )

    # Bulut kullanıcısı (sağ)
    if hub_user_display and hub_ip:
        ux, uy = w - 32, cy
        parts.append(
            f'<line x1="{cx + 46}" y1="{cy}" x2="{ux - 110}" y2="{uy}" stroke="#475569" stroke-width="1.2" marker-end="url(#kcArr)"/>'
            f'<rect x="{ux - 118}" y="{uy - 22}" width="136" height="44" rx="8" fill="#1e1b4b" stroke="#a78bfa"/>'
            f'<text x="{ux - 50}" y="{uy - 4}" text-anchor="middle" fill="#e9d5ff" font-size="10" font-weight="600" '
            f'font-family="Segoe UI,sans-serif">Bulut kimliği</text>'
            f'<text x="{ux - 50}" y="{uy + 12}" text-anchor="middle" fill="#c4b5fd" font-size="9" font-family="Consolas,monospace">'
            f"{esc(hub_user_display)}</text>"
        )

    parts.append("</svg>")
    return "\n".join(parts)

# Örnek / şablon kanıt matrisi (kanıt kaynağı → iz → DİZ kararı). Rapor HTML’inde gösterilir.
DEFAULT_EVIDENCE_MATRIX: list[dict[str, str]] = [
    {"source": "Mobil", "trace": 'WhatsApp: "Dosyaları buluta attım"', "decision": "Niyet Tespiti"},
    {"source": "Network", "trace": "192.168.1.5 -> 45.33.22.11 (HTTP POST)", "decision": "Veri Hırsızlığı"},
    {"source": "Cloud", "trace": "AWS: Snapshot_Delete (User: Admin)", "decision": "İzleri Silme Çabası"},
    {"source": "Disk/RAM", "trace": "PowerShell Injection + Event ID 4624", "decision": "Sızma Noktası"},
]


def _prepare_evidence_matrix(
    rows: list[dict[str, str]] | None,
    mask: bool,
) -> list[dict[str, str]]:
    """Kanıt kaynağı tablosu; ``mask=True`` iken ``mask_data`` ile KVKK uyumu."""
    from .masking import mask_data

    base = list(DEFAULT_EVIDENCE_MATRIX) if not rows else list(rows)
    out: list[dict[str, str]] = []
    for r in base:
        if not isinstance(r, dict):
            continue
        src = str(r.get("source") or r.get("Kanıt Kaynağı") or "")
        tr = str(r.get("trace") or r.get("Tespit Edilen İz") or "")
        de = str(
            r.get("decision")
            or r.get("diz_decision")
            or r.get("DİZ'in Kararı")
            or ""
        )
        if mask:
            src = mask_data(src)
            tr = mask_data(tr)
            de = mask_data(de)
        out.append({"source": src, "trace": tr, "decision": de})
    return out


def _level_to_class(level: str) -> str:
    """Seviyeyi CSS sınıfına map eder: Kritik=kırmızı, Düşük=sarı."""
    l = (level or "").lower().strip()
    if l in ("critical", "crit"):
        return "critical"
    if l in ("high", "yüksek"):
        return "high"
    if l in ("medium", "med", "orta"):
        return "medium"
    if l in ("low", "düşük"):
        return "low"
    return "info"


def _prepare_events(events: list[dict], mask: bool = True) -> list[dict]:
    """Olayları şablon için hazırlar, isteğe bağlı maskele. high_alert, confirmed_threat korunur."""
    from .masking import mask_data

    out = []
    for e in events:
        ts = str(e.get("Timestamp", "") or "")[:19]
        lv = str(e.get("Level", "") or "info")
        rt = str(e.get("RuleTitle", "") or "")[:120]
        dt = str(e.get("Details", "") or "")[:500]
        src = str(e.get("Source", "") or "").strip() or "Disk"
        if mask:
            rt = mask_data(rt)
            dt = mask_data(dt)
        mitre_raw = e.get("mitre_tags") if isinstance(e.get("mitre_tags"), list) else []
        mitre_tags_out: list[dict[str, str]] = []
        for t in mitre_raw:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("technique_id", ""))
            tname = str(t.get("technique_name", ""))[:80]
            tac = str(t.get("tactic_id", ""))
            mitre_tags_out.append(
                {
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic_id": tac,
                }
            )
        out.append(
            {
                "timestamp": ts,
                "level": lv,
                "level_class": _level_to_class(lv),
                "rule_title": rt,
                "details": dt,
                "source": src,
                "high_alert": bool(e.get("high_alert")),
                "confirmed_threat": bool(e.get("confirmed_threat")),
                "exfiltration_threat": bool(e.get("exfiltration_threat")),
                "account_takeover_threat": bool(e.get("account_takeover_threat")),
                "full_spectrum_threat": bool(e.get("full_spectrum_threat")),
                "mitre_tags": mitre_tags_out,
                "disk_ram_collision": False,
            }
        )
    return out


def _mask_threats_list(items: list[dict] | None, enabled: bool) -> list[dict]:
    from .masking import mask_structure

    if not items:
        return []
    if not enabled:
        return [dict(x) for x in items if isinstance(x, dict)]
    return mask_structure(items)  # type: ignore[return-value]


def _load_cross_alignment(mask: bool) -> dict[str, Any] | None:
    from .masking import mask_structure

    p = RESULTS / "cross_source_alignment.json"
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(raw, dict):
            return None
        if mask:
            return mask_structure(raw)  # type: ignore[return-value]
        return raw
    except (json.JSONDecodeError, OSError):
        return None


def _event_lane(source: str, rule_title: str) -> str:
    rt = (rule_title or "").upper()
    if source == "Zeek":
        return "Ağ"
    if source == "Volatility":
        if "NETWORK" in rt:
            return "RAM / Ağ (bellek)"
        return "RAM / Süreç"
    if source in ("Hayabusa", "Chainsaw"):
        return "Disk (EVTX)"
    return "Disk / Diğer"


def _parse_ts(ts: str) -> datetime | None:
    s = (ts or "").strip()[:19]
    if len(s) < 10:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00")[:19])
    except ValueError:
        return None


def _parse_cluster_time(s: str) -> datetime | None:
    s = str(s).replace("UTC", "").replace("–", "-").strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    return None


def _build_swimlane_markers(
    prepared: list[dict],
    cross_alignment: dict[str, Any] | None = None,
) -> tuple[list[dict], list[str], str | None]:
    """Yüzde konumlu saldırı haritası + correlator mobil/bulut kümesi işaretleri."""
    parsed: list[tuple[datetime, dict]] = []
    for e in prepared:
        d = _parse_ts(e.get("timestamp", ""))
        if d:
            parsed.append((d, e))
    t0 = min((x[0] for x in parsed), default=None)
    t1 = max((x[0] for x in parsed), default=None)
    if t0 is None:
        t0 = datetime.now()
    if t1 is None:
        t1 = t0
    span = (t1 - t0).total_seconds()
    if span <= 0:
        span = 1.0

    markers: list[dict[str, Any]] = []
    for d, e in sorted(parsed, key=lambda x: x[0]):
        pct = (d - t0).total_seconds() / span * 100
        lane = _event_lane(e.get("source", ""), e.get("rule_title", ""))
        cls = e.get("level_class", "info")
        if e.get("full_spectrum_threat"):
            cls = "critical"
        elif e.get("exfiltration_threat"):
            cls = "critical"
        elif e.get("confirmed_threat"):
            cls = "high"
        markers.append(
            {
                "left_pct": max(0.5, min(99.5, pct)),
                "lane": lane,
                "time": e.get("timestamp", ""),
                "label": (e.get("rule_title") or "")[:56],
                "level_class": cls,
            }
        )

    # Correlator: aynı pencerede mobil + bulut birlikteyse işaret
    if cross_alignment:
        for cl in (cross_alignment.get("ranked_by_coverage") or [])[:4]:
            srcs = set(cl.get("sources_present") or [])
            if "mobile" in srcs:
                dt = _parse_cluster_time(str(cl.get("time_start_utc", "")))
                if dt:
                    pct = (dt - t0).total_seconds() / span * 100
                    markers.append(
                        {
                            "left_pct": max(0.5, min(99.5, pct)),
                            "lane": "Mobil (çoklu kaynak kümesi)",
                            "time": str(cl.get("time_start_utc", ""))[:32],
                            "label": "WhatsApp / mobil kanıt (korelasyon)",
                            "level_class": "high",
                        }
                    )
            if "cloud" in srcs:
                dt = _parse_cluster_time(str(cl.get("time_start_utc", "")))
                if dt:
                    pct = (dt - t0).total_seconds() / span * 100
                    markers.append(
                        {
                            "left_pct": max(0.5, min(99.5, pct)),
                            "lane": "Bulut (çoklu kaynak kümesi)",
                            "time": str(cl.get("time_start_utc", ""))[:32],
                            "label": "CloudTrail / yetki olayı (korelasyon)",
                            "level_class": "critical",
                        }
                    )

    preferred = [
        "Mobil (çoklu kaynak kümesi)",
        "Bulut (çoklu kaynak kümesi)",
        "Ağ",
        "Disk (EVTX)",
        "Disk / Diğer",
        "RAM / Süreç",
        "RAM / Ağ (bellek)",
    ]
    lanes_used = {m["lane"] for m in markers}
    swimlane_lanes = [x for x in preferred if x in lanes_used] + sorted(
        lanes_used - set(preferred)
    )

    window = f"{t0.strftime('%Y-%m-%d %H:%M')} → {t1.strftime('%Y-%m-%d %H:%M')} UTC"
    return markers, swimlane_lanes, window


def _build_plotly_timeline_spec(prepared: list[dict]) -> str:
    """Plotly.js için JSON (harici kütüphane yok)."""
    xs: list[str] = []
    ys: list[str] = []
    colors: list[str] = []
    texts: list[str] = []
    color_map = {
        "critical": "#f85149",
        "high": "#da3633",
        "medium": "#d29922",
        "low": "#9e6a03",
        "info": "#58a6ff",
    }
    for e in prepared:
        ts = e.get("timestamp", "")
        if not _parse_ts(ts):
            continue
        lane = _event_lane(e.get("source", ""), e.get("rule_title", ""))
        xs.append(ts.replace(" ", "T"))
        ys.append(lane)
        lc = e.get("level_class", "info")
        colors.append(color_map.get(lc, "#58a6ff"))
        texts.append(f"{e.get('rule_title', '')}<br>{e.get('details', '')[:180]}")
    if not xs:
        return json.dumps({"data": [], "layout": {}})
    data = [
        {
            "x": xs,
            "y": ys,
            "mode": "markers",
            "type": "scatter",
            "marker": {"size": 12, "color": colors, "line": {"width": 1, "color": "#fff"}},
            "text": texts,
            "hovertemplate": "<b>%{text}</b><br>%{x}<extra></extra>",
        }
    ]
    layout = {
        "title": {"text": "Saldırı zaman çizelgesi (interaktif — KVKK maskeli)", "font": {"color": "#e6edf3"}},
        "xaxis": {
            "title": "Zaman",
            "gridcolor": "rgba(255,255,255,0.1)",
            "color": "#8b949e",
            "type": "date",
        },
        "yaxis": {"title": "Kaynak katmanı", "gridcolor": "rgba(255,255,255,0.08)", "color": "#8b949e"},
        "plot_bgcolor": "#161b22",
        "paper_bgcolor": "#0f1419",
        "font": {"color": "#e6edf3", "family": "Segoe UI, sans-serif"},
        "hovermode": "closest",
        "margin": {"l": 160, "r": 40, "t": 60, "b": 80},
    }
    return json.dumps({"data": data, "layout": layout}, ensure_ascii=False)


def _report_body_sha256(html_utf8: str) -> str:
    """UTF-8 rapor gövdesinin SHA-256 özeti (hex, küçük harf)."""
    return hashlib.sha256(html_utf8.encode("utf-8")).hexdigest()


def _integrity_footer_html(
    sha256_hex: str,
    output_name: str,
    verified_at_utc: str,
) -> str:
    """
    Rapor sonuna eklenen 'Rapor Doğrulama Özeti' HTML'i.
    Özet değeri, bu blok eklenmeden *önceki* gövdenin hash'idir (öz içermez).
    """
    return f"""
        <section id="diz-rapor-dogrulama" class="diz-integrity-footer" style="
            margin-top: 2.5rem;
            padding: 1.25rem 1.5rem;
            border: 1px solid #1e3a5f;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(0,240,255,0.04), rgba(31,111,235,0.06));
            font-size: 0.82rem;
            color: #c9d1d9;
        ">
            <h2 style="margin:0 0 0.75rem 0; font-size: 1rem; color: #58a6ff; letter-spacing: 0.03em; text-transform: uppercase;">
                Rapor Doğrulama Özeti — Dijital İmza (SHA-256)
            </h2>
            <p style="margin:0 0 0.65rem 0; line-height: 1.5;">
                Aşağıdaki <strong>SHA-256</strong> değeri, bu doğrulama bölümü üretilmeden hemen önceki
                rapor gövdesinin <em>UTF-8</em> bayt dizisi üzerinden hesaplanmıştır.
                Bu yöntem, <strong>EnCase</strong>, <strong>FTK Imager</strong> ve benzeri adli araçlarda
                kullanılan <strong>kanıt bütünlüğü (evidence integrity)</strong> ilkeleriyle uyumludur:
                rapor içeriğine sonradan yapılan değişiklikler, aynı gövde üzerinde yeniden üretilen özeti eşleştirmez.
            </p>
            <table style="width:100%; border-collapse: collapse; font-size: 0.8rem; margin: 0.5rem 0;">
                <tr><td style="padding: 0.35rem 0.5rem; color: #8b949e; width: 140px;">Dosya</td>
                    <td style="padding: 0.35rem 0.5rem;"><code style="color: #7ee7ff;">{output_name}</code></td></tr>
                <tr><td style="padding: 0.35rem 0.5rem; color: #8b949e;">Özet üretimi (UTC)</td>
                    <td style="padding: 0.35rem 0.5rem;">{verified_at_utc}</td></tr>
                <tr><td style="padding: 0.35rem 0.5rem; color: #8b949e; vertical-align: top;">SHA-256 (gövde)</td>
                    <td style="padding: 0.35rem 0.5rem; word-break: break-all; font-family: ui-monospace, Consolas, monospace; color: #f0b429;">
                        {sha256_hex}
                    </td></tr>
            </table>
            <p style="margin: 0.75rem 0 0 0; font-size: 0.75rem; color: #8b949e; font-style: italic;">
                Not: Bu bölüm dosyaya eklendikten sonra <strong>dosyanın tamamının</strong> SHA-256 değeri yukarıdakinden
                farklı olur; bütünlük denetiminde önce bu blok çıkarılıp veya gövde yeniden oluşturulup aynı yöntemle karşılaştırılmalıdır.
            </p>
        </section>
"""


def _insert_before_body_close(html: str, fragment: str) -> str:
    """``fragment``'i son ``</body>`` etiketinden hemen önce ekler."""
    marker = "</body>"
    idx = html.lower().rfind(marker)
    if idx == -1:
        return html + "\n" + fragment
    return html[:idx] + fragment + "\n    " + html[idx:]


def generate_html_report(
    events: list[dict],
    output_path: str | Path,
    title: str = DEFAULT_CASE_TITLE,
    subtitle: str = "Magnet AXIOM / Oxygen Forensics kalitesinde çoklu korelasyon özeti · KVKK kişisel veri maskelemesi",
    mask_sensitive: bool = True,
    confirmed_threats: list[dict] | None = None,
    exfiltration_threats: list[dict] | None = None,
    account_takeover_threats: list[dict] | None = None,
    full_spectrum_threats: list[dict] | None = None,
    cross_alignment: dict[str, Any] | None = None,
    evidence_matrix: list[dict[str, str]] | None = None,
    mitre_progress: dict[str, Any] | None = None,
    expert_opinions: list[dict[str, Any]] | None = None,
    analyst_storyline: str | None = None,
    cloud_payload: dict[str, Any] | None = None,
    mobile_payload: dict[str, Any] | None = None,
    section_analyst_notes: dict[str, str] | None = None,
    results_dir_for_hashes: Path | None = None,
) -> Path:
    """
    DİZ HTML vaka raporu.

    Args:
        events: Timeline olayları
        cross_alignment: ``build_cross_source_timestamp_alignment`` çıktısı; None ise diskten okunur
        evidence_matrix: Kanıt kaynağı / tespit / DİZ kararı satırları; None ise ``DEFAULT_EVIDENCE_MATRIX``
        mitre_progress: ``build_mitre_attack_progress_summary`` çıktısı; None ise olaylardan hesaplanır
        expert_opinions: Analist not defteri (Uzman Görüşü); None ise ``analyst_notebook.json`` okunur
        analyst_storyline: AI analist giriş özeti; None ise ``detective_report.md`` / ``attack_scenario.md``
        cloud_payload / mobile_payload: Storyline grafikleri için; None ise ``data/results`` üzerinden yüklenir
        section_analyst_notes: Bölüm altı analist notları; dosyadaki ``report_section_notes.json`` üzerine birleştirilir
        results_dir_for_hashes: Kanıt hash tablosu kökü; varsayılan ``data/results``
    """
    from jinja2 import Environment, FileSystemLoader

    from .analyst_notes import get_expert_opinions_for_report
    from .correlator import build_mitre_attack_progress_summary

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report.html")

    mp = mitre_progress if mitre_progress is not None else build_mitre_attack_progress_summary(events)
    opinions = (
        expert_opinions
        if expert_opinions is not None
        else get_expert_opinions_for_report(mask_sensitive=mask_sensitive)
    )
    prepared = _prepare_events(events, mask=mask_sensitive)
    _annotate_disk_ram_collision(events, prepared)
    conf_m = _mask_threats_list(confirmed_threats, mask_sensitive)
    ex_m = _mask_threats_list(exfiltration_threats, mask_sensitive)
    ato_m = _mask_threats_list(account_takeover_threats, mask_sensitive)
    fs_m = _mask_threats_list(full_spectrum_threats, mask_sensitive)

    align: dict[str, Any] | None = cross_alignment
    if align is None:
        align = _load_cross_alignment(mask_sensitive)
    elif mask_sensitive:
        from .masking import mask_structure

        align = mask_structure(align)  # type: ignore[assignment]

    swim_markers, swimlane_lanes, attack_window = _build_swimlane_markers(prepared, align)
    plotly_spec = _build_plotly_timeline_spec(prepared)
    evidence_rows = _prepare_evidence_matrix(evidence_matrix, mask_sensitive)

    cloud_pl = cloud_payload if cloud_payload is not None else _load_cloud_findings_disk()
    mobile_pl = mobile_payload if mobile_payload is not None else _load_mobile_findings_disk()
    narrative_html = narrative_paragraphs_to_html(
        load_analyst_storyline_narrative(mask_sensitive, analyst_storyline)
    )
    kill_chain = compute_kill_chain_three_stage(
        events,
        exfiltration_threats or [],
        confirmed_threats or [],
        account_takeover_threats or [],
        full_spectrum_threats or [],
        cloud_pl if isinstance(cloud_pl, dict) else {},
        mobile_pl if isinstance(mobile_pl, dict) else {},
    )
    storyline_vertical_timeline = build_storyline_vertical_timeline(
        prepared,
        mobile_pl if isinstance(mobile_pl, dict) else {},
        cloud_pl if isinstance(cloud_pl, dict) else {},
        align,
    )
    suspicious_files = collect_suspicious_file_paths_for_report()
    relationship_diagram_svg = build_relationship_diagram_svg(
        mask_sensitive,
        cloud_pl if isinstance(cloud_pl, dict) else {},
        suspicious_files,
    )
    story_flow_lines = build_narrative_story_flow_lines(storyline_vertical_timeline)

    sec_notes = load_section_analyst_notes(mask_sensitive)
    if section_analyst_notes:
        from .masking import mask_data

        for k, v in section_analyst_notes.items():
            if isinstance(k, str) and isinstance(v, str):
                t = v.strip()
                sec_notes[k] = mask_data(t) if mask_sensitive else t
    artifact_hash_rows = collect_results_artifact_hashes(results_dir_for_hashes or RESULTS)
    cover_manifest_sha256 = artifact_manifest_fingerprint_sha256(artifact_hash_rows)

    html = template.render(
        title=title,
        subtitle=subtitle,
        evidence_matrix=evidence_rows,
        events=prepared,
        confirmed_threats=conf_m,
        exfiltration_threats=ex_m,
        account_takeover_threats=ato_m,
        full_spectrum_threats=fs_m,
        cross_alignment=align or {},
        swimlane_markers=swim_markers,
        swimlane_lanes=swimlane_lanes,
        attack_window_label=attack_window or "",
        plotly_timeline_json=plotly_spec,
        mitre_progress=mp,
        expert_opinions=opinions,
        storyline_narrative_html=narrative_html,
        kill_chain=kill_chain,
        storyline_vertical_timeline=storyline_vertical_timeline,
        relationship_diagram_svg=relationship_diagram_svg,
        story_flow_lines=story_flow_lines,
        section_analyst_notes=sec_notes,
        artifact_hash_rows=artifact_hash_rows,
        cover_manifest_sha256=cover_manifest_sha256,
        kvkk_notice=(
            "Kişisel veriler (KVKK): Bu raporda IP, e-posta, kullanıcı adı ve benzeri tanımlayıcılar "
            "`core/masking.py` ile maskeleme uygulanarak üretilmiştir."
        ),
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Kanıt bütünlüğü: gövde hash'i → doğrulama özeti (EnCase / FTK tarzı integrity kaydı)
    body_digest = _report_body_sha256(html)
    verified_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    footer = _integrity_footer_html(body_digest, out.name, verified_at)
    html_with_integrity = _insert_before_body_close(html, footer)
    out.write_text(html_with_integrity, encoding="utf-8")

    return out


def generate_pdf_report(
    events: list[dict],
    output_path: str | Path,
    html_path: Optional[str | Path] = None,
    title: str = DEFAULT_CASE_TITLE,
    subtitle: str = "Magnet AXIOM / Oxygen Forensics kalitesinde çoklu korelasyon özeti · KVKK kişisel veri maskelemesi",
    mask_sensitive: bool = True,
    confirmed_threats: list[dict] | None = None,
    exfiltration_threats: list[dict] | None = None,
    account_takeover_threats: list[dict] | None = None,
    full_spectrum_threats: list[dict] | None = None,
    cross_alignment: dict[str, Any] | None = None,
    evidence_matrix: list[dict[str, str]] | None = None,
    mitre_progress: dict[str, Any] | None = None,
    expert_opinions: list[dict[str, Any]] | None = None,
    analyst_storyline: str | None = None,
    cloud_payload: dict[str, Any] | None = None,
    mobile_payload: dict[str, Any] | None = None,
    section_analyst_notes: dict[str, str] | None = None,
    results_dir_for_hashes: Path | None = None,
) -> Optional[Path]:
    """
    HTML raporunu PDF'e dönüştürür.
    Not: PDF motorları Plotly grafiğini statik olarak taşımayabilir; tablo ve yüzme hatları korunur.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    html_file = Path(html_path) if html_path else out.with_suffix(".html")
    generate_html_report(
        events,
        html_file,
        title=title,
        subtitle=subtitle,
        mask_sensitive=mask_sensitive,
        confirmed_threats=confirmed_threats,
        exfiltration_threats=exfiltration_threats,
        account_takeover_threats=account_takeover_threats,
        full_spectrum_threats=full_spectrum_threats,
        cross_alignment=cross_alignment,
        evidence_matrix=evidence_matrix,
        mitre_progress=mitre_progress,
        expert_opinions=expert_opinions,
        analyst_storyline=analyst_storyline,
        cloud_payload=cloud_payload,
        mobile_payload=mobile_payload,
        section_analyst_notes=section_analyst_notes,
        results_dir_for_hashes=results_dir_for_hashes,
    )

    try:
        import pdfkit

        pdfkit.from_file(str(html_file), str(out), options={"encoding": "UTF-8", "enable-local-file-access": ""})
        return out
    except (ImportError, OSError, Exception):
        pass

    try:
        from weasyprint import HTML

        HTML(filename=str(html_file)).write_pdf(str(out))
        return out
    except (ImportError, Exception):
        pass

    print("[!] PDF icin: pip install pdfkit (wkhtmltopdf) veya pip install weasyprint")
    return None
