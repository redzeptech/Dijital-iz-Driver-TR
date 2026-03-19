"""
DİZ Bağlam Motoru — Varlık (Entity) odaklı kanıt birleştirme.

Tek bir tanımlayıcı (ör. IPv4) seçildiğinde Zeek/Tshark çıktıları, AWS/Azure (CloudTrail / Activity)
kayıtları, Volatility netscan oturumları ve disk tabanlı timeline satırları tek bir **Varlık Kartı**
altında toplanır.

Tasarım atfı:
- **Arkime:** oturum/endpoint grafiği — kim kiminle, hangi yön ve port ile konuşmuş?
- **Cellebrite Pathfinder:** soruşturmacının tek bir varlık etrafında tüm dijital yüzeyleri pivot
  etmesi (kişi / oturum / uç nokta disiplini).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .utils import _flatten_vol_tree

_ROOT = Path(__file__).resolve().parent.parent
RESULTS = _ROOT / "data" / "results"

IPv4_RE = re.compile(
    r"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])"
)

ENTITY_TYPE_IP = "ip"


def _parse_sort_ts(s: str) -> float:
    """Basit zaman sıralaması (ilk 19 karakter ISO benzeri)."""
    if not s:
        return 0.0
    s = s.strip()[:19].replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def normalize_ipv4(value: str | None) -> str | None:
    """IPv4 dizesini normalize eder; geçersiz veya boş ise None."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip().strip('"').strip("'")
    if not s or s.lower() in ("-", "null", "none", "0.0.0.0"):
        return None
    if IPv4_RE.fullmatch(s):
        return s
    m2 = IPv4_RE.search(s)
    return m2.group(0) if m2 else None


def _iter_cloud_event_dicts(cloud_blob: Mapping[str, Any] | None) -> Iterator[dict[str, Any]]:
    if not cloud_blob:
        return
    for key in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
        chunk = cloud_blob.get(key)
        if not isinstance(chunk, list):
            continue
        for ev in chunk:
            if isinstance(ev, dict):
                yield ev


def _cloud_event_source_ip(ev: dict[str, Any]) -> str:
    for k in ("Source_IP", "source_ip", "sourceIPAddress", "client_ip", "sourceIp"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # İç içe AWS userIdentity / sessionContext
    ui = ev.get("user_identity") or ev.get("User_Identity")
    if isinstance(ui, str) and "@" not in ui:
        pass
    blob = json.dumps(ev, ensure_ascii=False)
    m = IPv4_RE.search(blob)
    return m.group(0) if m else ""


def _peer_endpoints_from_zeek_conn(rec: dict[str, Any]) -> tuple[str | None, str | None]:
    o = normalize_ipv4(str(rec.get("id.orig_h") or rec.get("orig_h") or ""))
    r = normalize_ipv4(str(rec.get("id.resp_h") or rec.get("resp_h") or ""))
    return o, r


def _zeek_ts(rec: dict[str, Any]) -> str:
    for k in ("ts", "time", "timestamp", "start_time"):
        v = rec.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s[:32]
    return ""


def _collect_ips_from_network_blob(net: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """network_analysis.json veya NetworkWrapper çıktısı: IP -> ham kayıt listeleri (tüm kanal)."""
    buckets: dict[str, list[tuple[str, dict[str, Any]]]] = {}

    def add(ip: str | None, channel: str, row: dict[str, Any]) -> None:
        if not ip:
            return
        buckets.setdefault(ip, []).append((channel, dict(row)))

    for key in ("connections", "http_traffic", "http_requests"):
        for row in net.get(key) or []:
            if not isinstance(row, dict):
                continue
            blob = json.dumps(row, ensure_ascii=False)
            for m in IPv4_RE.finditer(blob):
                ip = m.group(0)
                ch = "zeek_http" if key != "connections" else "zeek_connection"
                add(ip, ch, row)

    for key in ("dns_queries", "dns_tunneling_suspicious", "beaconing_suspicious"):
        for row in net.get(key) or []:
            if not isinstance(row, dict):
                continue
            blob = json.dumps(row, ensure_ascii=False)
            for m in IPv4_RE.finditer(blob):
                add(m.group(0), f"zeek_{key}", row)

    # buckets: ip -> list of (channel, row) — merge channels
    out: dict[str, list[dict[str, Any]]] = {}
    for ip, pairs in buckets.items():
        merged: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for channel, row in pairs:
            sig = (id(row), channel)
            if sig in seen:
                continue
            seen.add(sig)
            r = dict(row)
            r["_diz_channel"] = channel
            merged.append(r)
        out[ip] = merged
    return out


def _observations_from_zeek_rows(ip: str, rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    obs: list[dict[str, Any]] = []
    for row in rows:
        ch = str(row.get("_diz_channel", "zeek_network"))
        ts = _zeek_ts(row)
        title = ch.replace("_", " ").title()
        if "conn" in ch or ch == "zeek_connection":
            o, r = _peer_endpoints_from_zeek_conn(row)
            rp = row.get("id.resp_p") or row.get("resp_p") or row.get("tcp.dstport")
            lp = row.get("id.orig_p") or row.get("orig_p")
            detail = f"Oturum: orig={o}:{lp} resp={r}:{rp} proto={row.get('proto','?')}"
            if ip == o:
                peer = r
            else:
                peer = o
            title = f"Zeek conn — komşu {peer or '?'}"
        elif "http" in ch:
            host = row.get("host") or row.get("server_name") or ""
            method = row.get("method") or row.get("http.request.method") or ""
            uri = str(row.get("uri") or row.get("uri_original") or "")[:180]
            detail = f"{method} {host}{uri}"
            title = "Zeek HTTP"
        else:
            detail = json.dumps(row, ensure_ascii=False)[:400]

        obs.append(
            {
                "source": "zeek",
                "channel": ch,
                "timestamp": ts,
                "title": title,
                "detail": detail,
                "severity": "info",
            }
        )
    obs.sort(key=lambda x: _parse_sort_ts(str(x.get("timestamp", ""))))
    return obs


def _observations_from_cloud(ip: str, cloud_blob: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    obs: list[dict[str, Any]] = []
    if not cloud_blob:
        return obs
    for ev in _iter_cloud_event_dicts(cloud_blob):
        sip = normalize_ipv4(_cloud_event_source_ip(ev))
        if sip != ip:
            continue
        ts = str(ev.get("Timestamp") or ev.get("event_time") or ev.get("time") or "")[:32]
        action = str(ev.get("Action") or ev.get("event_name") or ev.get("operation_name") or "")
        user = str(ev.get("User_Identity") or ev.get("user_arn") or ev.get("privilege_summary") or "")
        status = str(ev.get("Status") or ev.get("status_normalized") or "")
        crit = bool(ev.get("critical") or ev.get("bulut_sizintisi") or ev.get("hybrid_attack"))
        sev = "critical" if crit else "medium"
        obs.append(
            {
                "source": "cloudtrail",
                "channel": "cloud_auth",
                "timestamp": ts,
                "title": action or "Cloud olayı",
                "detail": f"Kimlik: {user[:120]} | Durum: {status}"[:500],
                "severity": sev,
            }
        )
    obs.sort(key=lambda x: _parse_sort_ts(str(x.get("timestamp", ""))))
    return obs


def _observations_from_volatility_netscan(ip: str, netscan_data: Any) -> list[dict[str, Any]]:
    obs: list[dict[str, Any]] = []
    rows = _flatten_vol_tree(netscan_data)
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        loc = normalize_ipv4(str(raw.get("LocalAddress") or raw.get("local_address") or ""))
        rem = normalize_ipv4(str(raw.get("RemoteAddress") or raw.get("remote_address") or ""))
        if ip not in (loc, rem):
            continue
        ts_raw = raw.get("CreateTime") or raw.get("Created") or raw.get("timestamp")
        ts = str(ts_raw)[:32] if ts_raw is not None else ""
        pid = raw.get("PID") or raw.get("pid")
        proc = raw.get("Process") or raw.get("ImageFileName") or ""
        lp = raw.get("LocalPort") or raw.get("local_port")
        rp = raw.get("RemotePort") or raw.get("remote_port")
        st = raw.get("State") or raw.get("state")
        obs.append(
            {
                "source": "volatility",
                "channel": "windows.netscan",
                "timestamp": ts,
                "title": "Bellek netscan oturumu",
                "detail": f"Local {loc}:{lp} → Remote {rem}:{rp} | State: {st} | PID {pid} {proc}"[:500],
                "severity": "high",
            }
        )
    obs.sort(key=lambda x: _parse_sort_ts(str(x.get("timestamp", ""))))
    return obs


def _observations_from_timeline(ip: str, events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    obs: list[dict[str, Any]] = []
    if not events:
        return obs
    boundary = re.compile(r"(?<![0-9])" + re.escape(ip) + r"(?![0-9])")
    for ev in events:
        if not isinstance(ev, dict):
            continue
        blob = f"{ev.get('Details', '')} {ev.get('RuleTitle', '')} {ev.get('Source', '')}"
        if not boundary.search(blob):
            continue
        obs.append(
            {
                "source": "disk",
                "channel": "evtx_timeline",
                "timestamp": str(ev.get("Timestamp", ""))[:32],
                "title": str(ev.get("RuleTitle", "EVTX"))[:120],
                "detail": str(ev.get("Details", ""))[:500],
                "severity": str(ev.get("Level", "info")).lower(),
            }
        )
    obs.sort(key=lambda x: _parse_sort_ts(str(x.get("timestamp", ""))))
    return obs


def _arkime_style_session_hint(ip: str, network: Mapping[str, Any] | None) -> str:
    """Arkime oturum grafiği: bu IP'nin conn.log üzerinden gözle görülür komşuları."""
    if not network:
        return "Ağ özeti: PCAP/Zeek çıktısı yok."
    hints: list[str] = []
    seen: set[str] = set()
    for row in network.get("connections") or []:
        if not isinstance(row, dict):
            continue
        o, r = _peer_endpoints_from_zeek_conn(row)
        if ip == o and r:
            rp = row.get("id.resp_p") or row.get("resp_p") or "?"
            key = f"→ {r}:{rp}"
            if key not in seen:
                seen.add(key)
                hints.append(key)
        elif ip == r and o:
            lp = row.get("id.orig_p") or row.get("orig_p") or "?"
            key = f"← {o}:{lp}"
            if key not in seen:
                seen.add(key)
                hints.append(key)
        if len(hints) >= 12:
            break
    if not hints:
        return "Ağ: bu IP için Zeek conn komşusu eşleşmedi (HTTP/DNS veya tshark çıktısına bakın)."
    return "Oturum komşuları (Arkime tarzı uç nokta grafiği): " + "; ".join(hints[:10])


def _pathfinder_pivot_line(ip: str, sources: Sequence[str], facets: Mapping[str, Sequence[Any]]) -> str:
    """Cellebrite Pathfinder: tek varlık üzerinden tüm dijital kanıdı pivot et."""
    fk = " ".join(facets.keys())
    parts = [
        f"Uç nokta {ip} için {len(sources)} kaynak katmanı birleşti:",
        ", ".join(sorted(sources)),
        ".",
    ]
    if "cloudtrail" in fk:
        parts.append("Bulut oturum / API ayak izi mevcut.")
    if "volatility" in fk:
        parts.append("RAM'da aktif soket doğrulaması var.")
    if "zeek" in fk:
        parts.append("PCAP/Zeek oturumu ile zaman hizası mevcut.")
    if "disk" in fk:
        parts.append("EVTX disk kanıtında aynı adres referansı geçiyor.")
    return " ".join(parts)


@dataclass
class EntityCard:
    """JSON'a döşenebilir Varlık Kartı (IP)."""

    entity_type: str = ENTITY_TYPE_IP
    value: str = ""
    display_label: str = ""
    sources_present: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    facet_counts: dict[str, int] = field(default_factory=dict)
    facets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    arkime_session_summary: str = ""
    pathfinder_pivot: str = ""
    # İnceleyici notu (şablon / UI için)
    attribution: str = (
        "Varlık modeli: Arkime oturum grafiği + Cellebrite Pathfinder varlık-pivot disiplinine paralel."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "display_label": self.display_label,
            "sources_present": list(self.sources_present),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "facet_counts": dict(self.facet_counts),
            "facets": {k: v[:200] for k, v in self.facets.items()},
            "arkime_session_summary": self.arkime_session_summary,
            "pathfinder_pivot": self.pathfinder_pivot,
            "attribution": self.attribution,
        }


def _facet_key(obs: Mapping[str, Any]) -> str:
    return f"{obs.get('source', 'unknown')}_{obs.get('channel', 'generic')}".replace(".", "_")


def _trim_facets(facets: dict[str, list[dict[str, Any]]], per_facet: int = 120) -> None:
    for k in list(facets.keys()):
        facets[k] = facets[k][:per_facet]


def build_ip_entity_index(
    *,
    network_results: Mapping[str, Any] | None = None,
    cloud_blob: Mapping[str, Any] | None = None,
    volatility_results: Mapping[str, Any] | None = None,
    timeline_events: Sequence[dict[str, Any]] | None = None,
    max_observations_per_facet: int = 120,
) -> dict[str, EntityCard]:
    """
    Tüm kaynaklardan IPv4 varlıklarını çıkarır ve birleşik Varlık Kartları üretir.

    Args:
        network_results: ``NetworkWrapper.run_analysis`` dönüşü veya ``network_analysis.json`` gövdesi
        cloud_blob: ``cloud_findings.json`` sözlüğü
        volatility_results: ``VolatilityWrapper.run_analysis`` benzeri ``{\"results\": {\"windows.netscan\": ...}}``
        timeline_events: Hayabusa+Chainsaw+Volatility birleşik olay listesi (Details içinde IP aranır)
    """
    net = dict(network_results) if network_results else {}
    vol_ns: Any = None
    if volatility_results:
        res = volatility_results.get("results") or {}
        vol_ns = res.get("windows.netscan") or res.get("windows.netscan.NetScan")

    # IP -> raw zeek rows (tagged)
    zeek_by_ip = _collect_ips_from_network_blob(net)

    all_ips: set[str] = set(zeek_by_ip.keys())
    for ev in _iter_cloud_event_dicts(cloud_blob):
        sip = normalize_ipv4(_cloud_event_source_ip(ev))
        if sip:
            all_ips.add(sip)
    if vol_ns:
        for raw in _flatten_vol_tree(vol_ns):
            if not isinstance(raw, dict):
                continue
            for key in ("LocalAddress", "RemoteAddress", "local_address", "remote_address"):
                ip = normalize_ipv4(str(raw.get(key) or ""))
                if ip:
                    all_ips.add(ip)
    if timeline_events:
        for ev in timeline_events:
            if not isinstance(ev, dict):
                continue
            blob = f"{ev.get('Details', '')} {ev.get('RuleTitle', '')}"
            for m in IPv4_RE.finditer(blob):
                all_ips.add(m.group(0))

    cards: dict[str, EntityCard] = {}
    for ip in sorted(all_ips):
        facets: dict[str, list[dict[str, Any]]] = {}

        zrows = zeek_by_ip.get(ip, [])
        if zrows:
            zobs = _observations_from_zeek_rows(ip, zrows)
            for o in zobs:
                fk = _facet_key(o)
                facets.setdefault(fk, []).append(o)

        for o in _observations_from_cloud(ip, cloud_blob):
            fk = _facet_key(o)
            facets.setdefault(fk, []).append(o)

        for o in _observations_from_volatility_netscan(ip, vol_ns):
            fk = _facet_key(o)
            facets.setdefault(fk, []).append(o)

        for o in _observations_from_timeline(ip, timeline_events or ()):
            fk = _facet_key(o)
            facets.setdefault(fk, []).append(o)

        if not facets:
            continue

        _trim_facets(facets, max_observations_per_facet)

        sources = sorted({str(o.get("source")) for fl in facets.values() for o in fl if o.get("source")})
        facet_counts = {k: len(v) for k, v in facets.items()}
        all_ts: list[str] = []
        for fl in facets.values():
            for o in fl:
                t = str(o.get("timestamp") or "").strip()
                if t:
                    all_ts.append(t)
        all_ts.sort(key=_parse_sort_ts)
        first = all_ts[0] if all_ts else ""
        last = all_ts[-1] if all_ts else ""

        card = EntityCard(
            value=ip,
            display_label=f"IPv4 — {ip}",
            sources_present=sources,
            first_seen=first,
            last_seen=last,
            facet_counts=facet_counts,
            facets=facets,
            arkime_session_summary=_arkime_style_session_hint(ip, net),
            pathfinder_pivot=_pathfinder_pivot_line(ip, sources, facets),
        )
        cards[ip] = card

    return cards


def get_ip_entity_card(
    ip: str,
    *,
    network_results: Mapping[str, Any] | None = None,
    cloud_blob: Mapping[str, Any] | None = None,
    volatility_results: Mapping[str, Any] | None = None,
    timeline_events: Sequence[dict[str, Any]] | None = None,
) -> EntityCard | None:
    """Tek IP için Varlık Kartı (tüm index üzerinden seçim)."""
    key = normalize_ipv4(ip)
    if not key:
        return None
    idx = build_ip_entity_index(
        network_results=network_results,
        cloud_blob=cloud_blob,
        volatility_results=volatility_results,
        timeline_events=timeline_events,
    )
    return idx.get(key)


def load_results_bundle(
    results_dir: str | Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """
    ``data/results`` altından tipik JSON dosyalarını yükler (UI / hızlı pivot).

    Returns:
        (network_analysis, cloud_findings, volatility_bundle_or_none)
    """
    base = Path(results_dir) if results_dir else RESULTS
    net: dict[str, Any] = {}
    p_net = base / "network_analysis.json"
    if p_net.exists():
        try:
            net = json.loads(p_net.read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(net, dict):
                net = {}
        except (json.JSONDecodeError, OSError):
            net = {}

    cloud: dict[str, Any] = {}
    p_cloud = base / "cloud_findings.json"
    if p_cloud.exists():
        try:
            cloud = json.loads(p_cloud.read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(cloud, dict):
                cloud = {}
        except (json.JSONDecodeError, OSError):
            cloud = {}

    vol_bundle: dict[str, Any] | None = None
    vdir = base / "volatility"
    if vdir.is_dir():
        results_inner: dict[str, Any] = {}
        for fname, key in (
            ("windows_netscan.json", "windows.netscan"),
            ("windows_pslist.json", "windows.pslist"),
        ):
            fp = vdir / fname
            if fp.exists():
                try:
                    results_inner[key] = json.loads(fp.read_text(encoding="utf-8", errors="ignore"))
                except (json.JSONDecodeError, OSError):
                    continue
        if results_inner:
            vol_bundle = {"success": True, "results": results_inner}

    return net, cloud, vol_bundle


def export_entity_index_json(
    output_path: str | Path,
    *,
    network_results: Mapping[str, Any] | None = None,
    cloud_blob: Mapping[str, Any] | None = None,
    volatility_results: Mapping[str, Any] | None = None,
    timeline_events: Sequence[dict[str, Any]] | None = None,
) -> Path:
    """Varlık indeksini JSON dosyasına yazar (rapor / SIEM dış aktarım)."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    idx = build_ip_entity_index(
        network_results=network_results,
        cloud_blob=cloud_blob,
        volatility_results=volatility_results,
        timeline_events=timeline_events,
    )
    payload = {ip: card.to_dict() for ip, card in idx.items()}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out
