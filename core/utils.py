"""
Dijital İz Sürücü - Yardımcı Fonksiyonlar
Hayabusa, Chainsaw ve Volatility çıktılarını standart formata dönüştürür.
SuperTimeline: Disk + Bellek olayları tek zaman çizelgesinde.
"""

import re
from datetime import datetime
from typing import Any

# Standart olay yapısı
STANDARD_EVENT_KEYS = ("Timestamp", "Level", "RuleTitle", "Details")


def _get_value(data: dict, keys: tuple[str, ...], default: str = "") -> str:
    """Sözlükten ilk eşleşen anahtarın değerini döndürür."""
    for key in keys:
        if key in data and data[key] is not None:
            val = data[key]
            return str(val).strip() if val else default
    return default


def normalize_event(raw_data: dict[str, Any], source_tool: str) -> dict[str, str]:
    """
    Hayabusa veya Chainsaw ham çıktısını standart sözlük yapısına çevirir.

    Standart yapı: Timestamp, Level, RuleTitle, Details

    Args:
        raw_data: Tek bir olayın ham verisi (dict)
        source_tool: "Hayabusa" veya "Chainsaw"

    Returns:
        {"Timestamp": ..., "Level": ..., "RuleTitle": ..., "Details": ...}
    """
    if not isinstance(raw_data, dict):
        return {k: "" for k in STANDARD_EVENT_KEYS}

    source = str(source_tool).strip().lower()

    if source == "hayabusa":
        return _normalize_hayabusa(raw_data)
    if source == "chainsaw":
        return _normalize_chainsaw(raw_data)
    if source in ("volatility", "volatility_netscan"):
        return _normalize_volatility_netscan(raw_data)
    if source == "volatility_pslist":
        return _normalize_volatility_pslist(raw_data)

    return {k: "" for k in STANDARD_EVENT_KEYS}


def _normalize_hayabusa(raw: dict) -> dict[str, str]:
    """Hayabusa JSON çıktısını standart yapıya çevirir."""
    timestamp_keys = ("Timestamp", "timestamp", "time", "TimeCreated")
    level_keys = ("Level", "level", "Severity", "severity")
    rule_keys = ("RuleTitle", "Rule Title", "rule_title", "Title")
    details_keys = ("Details", "details", "ExtraFieldInfo", "message", "Description")

    return {
        "Timestamp": _get_value(raw, timestamp_keys),
        "Level": _get_value(raw, level_keys),
        "RuleTitle": _get_value(raw, rule_keys),
        "Details": _get_value(raw, details_keys),
    }


def _normalize_chainsaw(raw: dict) -> dict[str, str]:
    """Chainsaw çıktısını standart yapıya çevirir."""
    timestamp_keys = (
        "Timestamp",
        "timestamp",
        "time",
        "Event.System.TimeCreated.SystemTime",
        "TimeCreated",
    )
    level_keys = ("level", "Level", "severity", "Severity")
    rule_keys = ("Rule Title", "RuleTitle", "rule_title", "detections", "Detection", "Title")
    details_keys = (
        "Event Data",
        "EventData",
        "Details",
        "details",
        "message",
        "Description",
    )

    details = _get_value(raw, details_keys)
    if not details:
        event_id = _get_value(raw, ("EventID", "event_id", "Event.System.EventID", "EventId"))
        if event_id:
            details = f"EventID: {event_id}"

    return {
        "Timestamp": _get_value(raw, timestamp_keys),
        "Level": _get_value(raw, level_keys),
        "RuleTitle": _get_value(raw, rule_keys),
        "Details": details,
    }


def _flatten_vol_tree(data: Any) -> list[dict]:
    """Volatility JSON tree yapısını (__children) düz listeye çevirir."""
    if isinstance(data, list):
        out = []
        for item in data:
            out.extend(_flatten_vol_tree(item))
        return out
    if isinstance(data, dict):
        if "__children" in data:
            row = {k: v for k, v in data.items() if k != "__children"}
            out = [row] if row else []
            for c in data.get("__children", []):
                out.extend(_flatten_vol_tree(c))
            return out
        return [data]
    return []


def _vol_timestamp_to_iso(val: Any) -> str:
    """Volatility timestamp'ını ISO benzeri formata çevirir."""
    if val is None:
        return ""
    s = str(val).strip()
    if not s:
        return ""
    # Zaten ISO format (örn. 2024-01-15 10:30:00)
    if re.match(r"\d{4}-\d{2}-\d{2}", s):
        return s[:19]
    try:
        ts = float(s)
        # Windows filetime (100ns since 1601) -> Unix
        if ts > 1e16:
            ts = (ts - 116444736000000000) / 10000000
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        pass
    return s


def _normalize_volatility_netscan(raw: dict) -> dict[str, str]:
    """Volatility windows.netscan çıktısını standart yapıya çevirir. NETWORK_MEMORY etiketi."""
    ts_keys = ("CreateTime", "Created", "TimeCreated", "timestamp", "Timestamp")
    local_keys = ("LocalAddress", "LocalAddr", "local_address")
    remote_keys = ("RemoteAddress", "RemoteAddr", "remote_address")
    port_keys = ("LocalPort", "RemotePort", "local_port", "remote_port")
    state_keys = ("State", "state")
    pid_keys = ("PID", "pid", "ProcessId")
    process_keys = ("Process", "process", "ImageFileName")

    timestamp = _get_value(raw, ts_keys)
    if timestamp:
        timestamp = _vol_timestamp_to_iso(timestamp)
    local = _get_value(raw, local_keys)
    remote = _get_value(raw, remote_keys)
    lp = _get_value(raw, ("LocalPort", "local_port"))
    rp = _get_value(raw, ("RemotePort", "remote_port"))
    state = _get_value(raw, state_keys)
    pid = _get_value(raw, pid_keys)
    proc = _get_value(raw, process_keys)

    details = f"Local: {local}:{lp} -> Remote: {remote}:{rp}"
    if state:
        details += f" | State: {state}"
    if pid:
        details += f" | PID: {pid}"
    if proc:
        details += f" | Process: {proc}"

    return {
        "Timestamp": timestamp or "",
        "Level": "info",
        "RuleTitle": "NETWORK_MEMORY",
        "Details": details.strip(),
    }


def _normalize_volatility_pslist(raw: dict) -> dict[str, str]:
    """Volatility windows.pslist çıktısını standart yapıya çevirir. Süreç başlama zamanı."""
    ts_keys = ("CreateTime", "Created", "TimeCreated", "timestamp", "Timestamp")
    pid_keys = ("PID", "pid", "ProcessId")
    process_keys = ("Process", "process", "ImageFileName", "Image")
    ppid_keys = ("PPID", "ppid", "ParentProcessId")

    timestamp = _get_value(raw, ts_keys)
    if timestamp:
        timestamp = _vol_timestamp_to_iso(timestamp)
    pid = _get_value(raw, pid_keys)
    proc = _get_value(raw, process_keys)
    ppid = _get_value(raw, ppid_keys)

    details = f"PID: {pid}"
    if proc:
        details += f" | Process: {proc}"
    if ppid:
        details += f" | PPID: {ppid}"

    return {
        "Timestamp": timestamp or "",
        "Level": "info",
        "RuleTitle": "PROCESS_MEMORY",
        "Details": details.strip(),
    }


def normalize_volatility_netscan_batch(netscan_data: Any) -> list[dict[str, str]]:
    """
    Volatility windows.netscan ham çıktısını timeline'e eklenebilir olay listesine çevirir.
    NETWORK_MEMORY etiketiyle ana zaman çizelgesine eklenir.

    Args:
        netscan_data: Volatility JSON çıktısı (dict veya __children tree)

    Returns:
        Standart yapıda olay listesi
    """
    rows = _flatten_vol_tree(netscan_data)
    return [normalize_event(r, "volatility_netscan") for r in rows if isinstance(r, dict)]


def normalize_volatility_pslist_batch(pslist_data: Any) -> list[dict[str, str]]:
    """
    Volatility windows.pslist çıktısını standart yapıya çevirir.
    Süreç başlama zamanlarını timeline'e ekler (PROCESS_MEMORY).
    """
    rows = _flatten_vol_tree(pslist_data)
    return [normalize_event(r, "volatility_pslist") for r in rows if isinstance(r, dict)]


# Bulut günlükleri (AWS CloudTrail / Azure Activity) — DİZ export birleşik şeması
CLOUD_EVENT_STANDARD_KEYS = ("Timestamp", "User_Identity", "Action", "Source_IP", "Status")


def standardize_cloud_event_row(ev: dict[str, Any]) -> dict[str, str]:
    """
    ``modules.cloud_wrapper`` çıktısındaki zengin olayı beş ana sütuna indirger.
    Hayabusa/Chainsaw ile aynı disiplin: düz ``str`` değerler, rapor / SIEM uyumu.

    Anahtarlar: Timestamp, User_Identity, Action, Source_IP, Status
    """
    if not isinstance(ev, dict):
        return {k: "" for k in CLOUD_EVENT_STANDARD_KEYS}
    ts = _get_value(ev, ("Timestamp", "event_time", "time"))
    action = _get_value(ev, ("Action", "event_name", "operation_name"))
    uid = _get_value(ev, ("User_Identity", "privilege_summary", "user_arn"))
    sip = _get_value(ev, ("Source_IP", "source_ip"))
    status = _get_value(ev, ("Status", "status_normalized"))
    return {
        "Timestamp": ts,
        "User_Identity": uid,
        "Action": action,
        "Source_IP": sip,
        "Status": status,
    }


def normalize_events_batch(
    raw_events: list[dict],
    source_tool: str,
) -> list[dict[str, str]]:
    """
    Olay listesini toplu normalize eder.
    Ana programda iki aracın verisini birleştirmek için kullanılır.

    Args:
        raw_events: Ham olay listesi
        source_tool: "Hayabusa", "Chainsaw", "volatility_netscan", "volatility_pslist"

    Returns:
        Standart yapıda olay listesi
    """
    return [normalize_event(e, source_tool) for e in raw_events if isinstance(e, dict)]
