"""
Dijital İz Sürücü - Ana Uygulama (Vitrin)
Hayabusa, Chainsaw, Volatility, Zeek verilerini tek Saldırı Zaman Çizelgesi'nde birleştirir.

Arkime derinliği + Magnet AXIOM kullanılabilirliği — "Siber Savaş Odası" arayüzü.
"""

from __future__ import annotations

import html
import json
import re
import sys
import time
import urllib.error
import urllib.request
import math
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "results"

IP_V4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)

SUSPICIOUS_EXT = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".sys")


def _load_json(path: Path) -> list | dict:
    if not path.exists():
        return [] if "list" in str(type(path)) else {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data] if data else []
    except (json.JSONDecodeError, Exception):
        return []


def _load_json_dict(path: Path) -> dict[str, Any]:
    """Kökü nesne olan JSON (cloud_findings, mobile_findings) için."""
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, Exception):
        return {}


def _flatten_vol_tree(data: Any) -> list[dict]:
    """Volatility ağaç çıktısını düz liste yapar (correlator ile uyumlu)."""
    if isinstance(data, list):
        out: list[dict] = []
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


def _is_private_ip(ip: str) -> bool:
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        o = [int(x) for x in parts]
    except ValueError:
        return True
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    return False


def _is_plausible_ip(ip: str) -> bool:
    """Maskeleme veya geçersiz IP'leri ele."""
    if not ip or "*" in ip or "xxx" in ip.lower():
        return False
    if not IP_V4.fullmatch(ip.strip()):
        return False
    return not _is_private_ip(ip.strip())


def _collect_ips_from_network(net: dict | list | None, priority_lists: tuple[str, ...]) -> dict[str, str]:
    """Şüpheli kaynak listelerinden IP -> etiket eşlemesi."""
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
                ip = m.group(0)
                if _is_plausible_ip(ip) and ip not in ip_labels:
                    ip_labels[ip] = label
    return ip_labels


def _ips_from_volatility_netscan() -> dict[str, str]:
    out: dict[str, str] = {}
    path = RESULTS / "volatility" / "windows_netscan.json"
    data = _load_json(path)
    if isinstance(data, dict) and "__children" in data:
        rows = _flatten_vol_tree(data)
    elif isinstance(data, list):
        rows = [x for x in data if isinstance(x, dict)]
    else:
        rows = []
    for r in rows:
        ra = str(r.get("RemoteAddress") or r.get("remote_address") or "")
        for m in IP_V4.finditer(ra):
            ip = m.group(0)
            if _is_plausible_ip(ip):
                out.setdefault(ip, "Volatility netscan")
    return out


@st.cache_data(ttl=3600, show_spinner="Şüpheli IP'ler için konum (ülke) çözülüyor…")
def _geolocate_ips_cached(ips_tuple: tuple[str, ...]) -> list[dict]:
    """ip-api.com (ücretsiz katman, rate limit: düşük hacim)."""
    rows: list[dict] = []
    for ip in ips_tuple:
        if not _is_plausible_ip(ip):
            continue
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,lat,lon,query"
            req = urllib.request.Request(url, headers={"User-Agent": "DijitalIzDashboard/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if data.get("status") != "success":
                continue
            lat, lon = data.get("lat"), data.get("lon")
            if lat is None or lon is None:
                continue
            rows.append(
                {
                    "ip": ip,
                    "lat": float(lat),
                    "lon": float(lon),
                    "country": data.get("country") or "?",
                    "countryCode": data.get("countryCode") or "",
                }
            )
            time.sleep(0.05)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, TypeError):
            continue
    return rows


def build_threat_map_data(mask_sensitive: bool) -> tuple[pd.DataFrame, list[str]]:
    """
    Ağ trafiği + Volatility netscan üzerinden şüpheli IP'leri toplar ve coğrafi koordinat üretir.
    Maskeleme açıksa dosyada zaten maskelenmiş IP varsa harita atlanır.
    """
    notes: list[str] = []
    net = _load_json(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}

    ip_src: dict[str, str] = {}
    ip_src.update(
        _collect_ips_from_network(
            net,
            ("beaconing_suspicious", "dns_tunneling_suspicious", "connections", "http_traffic"),
        )
    )
    ip_src.update(_ips_from_volatility_netscan())

    if mask_sensitive:
        sample = json.dumps(net, ensure_ascii=False)[:500]
        if "*" in sample or "xxx" in sample.lower():
            notes.append("KVKK maskesi: ham IP yok; harita için maskeli görüntüyü kapatın veya yeniden analiz yapın.")
            return pd.DataFrame(), notes

    if not ip_src:
        notes.append("Şüpheli dış IP bulunamadı (PCAP/Zeek veya Volatility netscan çıktısı gerekir).")
        return pd.DataFrame(), notes

    ips_sorted = tuple(sorted(ip_src.keys()))
    geo = _geolocate_ips_cached(ips_sorted)
    if not geo:
        notes.append("Konum servisi yanıt vermedi veya tüm IP'ler özel aralıkta.")
        return pd.DataFrame(), notes

    df = pd.DataFrame(geo)
    df["source"] = df["ip"].map(lambda x: ip_src.get(x, "Ağ"))
    df["label"] = df["country"] + " — " + df["ip"] + " (" + df["source"] + ")"
    df["tip_line2"] = df["ip"].astype(str) + " · " + df["source"].astype(str)
    return df, notes


def load_cloud_findings() -> dict[str, Any]:
    return _load_json_dict(RESULTS / "cloud_findings.json")


def load_mobile_findings() -> dict[str, Any]:
    return _load_json_dict(RESULTS / "mobile_findings.json")


def build_mobile_gps_map_df(mobile: dict[str, Any], max_trail_points: int = 15) -> pd.DataFrame:
    """
    Yedekten çıkarılan konum satırları — zaman sırasına göre son N nokta (iz + son konum vurgusu).
    """
    locs = mobile.get("locations") or []
    rows: list[dict[str, Any]] = []
    for L in locs:
        if not isinstance(L, dict):
            continue
        try:
            la_f = float(L["latitude"])
            lo_f = float(L["longitude"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (-90 <= la_f <= 90 and -180 <= lo_f <= 180):
            continue
        rows.append(
            {
                "lat": la_f,
                "lon": lo_f,
                "kind": "Mobil GPS",
                "table": str(L.get("table", ""))[:80],
                "timestamp_iso": str(L.get("timestamp_iso", "")),
                "source_db": str(L.get("source_db", ""))[-60:],
            }
        )
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["_ts"] = pd.to_datetime(df["timestamp_iso"], errors="coerce")
    df = df.sort_values("_ts", na_position="first")
    trail = df.tail(max_trail_points).drop(columns=["_ts"], errors="ignore").reset_index(drop=True)
    trail["is_latest"] = trail.index == len(trail) - 1
    trail["radius"] = trail["is_latest"].map(lambda x: 220_000 if x else 95_000)
    trail["label"] = trail.apply(
        lambda r: (
            f"**Son mobil konum** · {r.get('table', '')}"
            if r.get("is_latest")
            else f"Mobil GPS · {r.get('table', '')}"
        ),
        axis=1,
    )
    trail["tip_line2"] = trail["timestamp_iso"].astype(str) + " · " + trail["source_db"].astype(str)
    return trail


def build_mobile_route_last_hours_df(
    mobile: dict[str, Any],
    hours: int = 24,
) -> tuple[pd.DataFrame, str | None]:
    """
    GPS içeren konum satırlarından, zaman damgası varsa son `hours` saatlik sıralı rota.
    Dönen ikinci değer: kullanıcıya gösterilecek bilgi notu (süzme / zaman eksikliği).
    """
    locs = mobile.get("locations") or []
    rows: list[dict[str, Any]] = []
    for L in locs:
        if not isinstance(L, dict):
            continue
        try:
            la_f = float(L["latitude"])
            lo_f = float(L["longitude"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (-90 <= la_f <= 90 and -180 <= lo_f <= 180):
            continue
        rows.append(
            {
                "lat": la_f,
                "lon": lo_f,
                "timestamp_iso": str(L.get("timestamp_iso", "")),
                "table": str(L.get("table", ""))[:80],
                "source_db": str(L.get("source_db", ""))[-80:],
            }
        )
    if not rows:
        return pd.DataFrame(), None

    df = pd.DataFrame(rows)
    df["_ts"] = pd.to_datetime(df["timestamp_iso"], errors="coerce", utc=True)
    valid = df.dropna(subset=["_ts"])
    note: str | None = None
    if len(valid) == 0:
        note = "Konumlarda geçerli zaman damgası yok — GPS noktaları saklanan sırayla gösteriliyor."
        out = df.sort_index()
    else:
        ref = valid["_ts"].max()
        cutoff = ref - pd.Timedelta(hours=hours)
        out = valid[valid["_ts"] >= cutoff].sort_values("_ts").copy()
        dropped = len(valid) - len(out)
        if dropped > 0:
            note = f"Son {hours} saat: {len(out)} / {len(valid)} zamanlı nokta (daha eski kayıtlar süzüldü)."
    out = out.drop(columns=["_ts"], errors="ignore").reset_index(drop=True)
    return out, note


def build_unified_mobile_chat_dataframe(mobile: dict[str, Any]) -> pd.DataFrame:
    """WhatsApp + SMS — tek zaman çizelgesi için normalize edilmiş tablo."""
    chunk: list[dict[str, Any]] = []
    for m in mobile.get("whatsapp_messages") or []:
        if not isinstance(m, dict):
            continue
        jid = str(m.get("jid") or m.get("chat_jid") or m.get("sender_jid") or "")
        chunk.append(
            {
                "channel": "whatsapp",
                "peer": jid,
                "body": str(m.get("body", "")),
                "from_me": m.get("from_me"),
                "timestamp_iso": str(m.get("timestamp_iso", "")),
            }
        )
    for m in mobile.get("sms_messages") or []:
        if not isinstance(m, dict):
            continue
        peer = str(m.get("address") or m.get("peer") or "")
        chunk.append(
            {
                "channel": "sms",
                "peer": peer,
                "body": str(m.get("body", "")),
                "from_me": m.get("from_me"),
                "timestamp_iso": str(m.get("timestamp_iso", "")),
            }
        )
    if not chunk:
        return pd.DataFrame(columns=["channel", "peer", "body", "from_me", "timestamp_iso", "_ts"])
    cdf = pd.DataFrame(chunk)
    cdf["_ts"] = pd.to_datetime(cdf["timestamp_iso"], errors="coerce", utc=True)
    cdf = cdf.sort_values("_ts", na_position="first")
    return cdf


def _mobile_chat_thread_options(cdf: pd.DataFrame) -> list[tuple[str, str | None, str | None]]:
    """Etiket, kanal filtresi ('whatsapp'|'sms'|None), peer."""
    opts: list[tuple[str, str | None, str | None]] = [
        ("📋 Tüm mesajlar (WhatsApp + SMS, kronolojik)", None, None),
    ]
    if len(cdf) == 0:
        return opts
    wa = cdf[cdf["channel"] == "whatsapp"]
    if len(wa) > 0:
        for jid, sub in wa.groupby("peer"):
            n = len(sub)
            if not jid:
                continue
            short = (jid[:42] + "…") if len(jid) > 44 else jid
            opts.append((f"WhatsApp · {short} ({n})", "whatsapp", jid))
    sm = cdf[cdf["channel"] == "sms"]
    if len(sm) > 0:
        for addr, sub in sm.groupby("peer"):
            n = len(sub)
            label_peer = addr or "(numara yok)"
            opts.append((f"SMS · {label_peer} ({n})", "sms", addr or ""))
    return opts


def render_mobile_chat_bubble_timeline(cdf: pd.DataFrame, channel: str | None, peer: str | None) -> None:
    """Karşılıklı konuşma baloncukları (Streamlit HTML)."""
    if len(cdf) == 0:
        st.info("WhatsApp veya SMS mesajı yok — `msgstore.db` / `mmssms.db` içeren yedek analiz edin.")
        return
    work = cdf.copy()
    if channel and peer is not None:
        work = work[(work["channel"] == channel) & (work["peer"] == peer)]
    elif channel:
        work = work[work["channel"] == channel]
    work = work.sort_values("_ts", na_position="first")
    max_n = 450
    if len(work) > max_n:
        st.caption(
            f"Son {max_n} mesaj gösteriliyor (performans). Tam tablo için **Mobil Kanıtlar** sekmesini kullanın."
        )
        work = work.tail(max_n)
    style = """
    <style>
    .dijitaliz-chat-wrap {
        font-family: "Segoe UI", "IBM Plex Sans", sans-serif;
        max-height: 560px;
        overflow-y: auto;
        padding: 12px 8px;
        border-radius: 10px;
        background: linear-gradient(180deg, #0d1117 0%, #0a1628 100%);
        border: 1px solid #21262d;
    }
    .dijitaliz-chat-row { display: flex; margin: 8px 0; width: 100%; }
    .dijitaliz-me { justify-content: flex-end; }
    .dijitaliz-them { justify-content: flex-start; }
    .dijitaliz-bubble {
        max-width: 78%;
        padding: 10px 14px;
        border-radius: 16px;
        font-size: 0.95rem;
        line-height: 1.45;
        color: #e6edf3;
        word-break: break-word;
    }
    .dijitaliz-me .dijitaliz-bubble {
        background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%);
        border: 1px solid rgba(56,139,253,0.5);
        border-bottom-right-radius: 4px;
    }
    .dijitaliz-them .dijitaliz-bubble {
        background: #21262d;
        border: 1px solid #30363d;
        border-bottom-left-radius: 4px;
    }
    .dijitaliz-meta {
        font-size: 0.72rem;
        opacity: 0.82;
        margin-top: 6px;
        color: #8b949e;
        font-variant-numeric: tabular-nums;
    }
    .dijitaliz-chan { color: #58a6ff; font-weight: 600; margin-right: 6px; }
    </style>
    """
    parts = [style, '<div class="dijitaliz-chat-wrap">']
    for _, row in work.iterrows():
        fm = row.get("from_me")
        if fm is True:
            side = "dijitaliz-me"
        elif fm is False:
            side = "dijitaliz-them"
        else:
            side = "dijitaliz-them"
        if row.get("channel") == "whatsapp":
            tag = "WA"
        else:
            tag = "SMS"
        ts = row.get("timestamp_iso") or ""
        meta = f'<span class="dijitaliz-chan">{tag}</span>{html.escape(str(ts))}'
        body = row.get("body") or " "
        body_esc = html.escape(str(body)).replace("\n", "<br/>")
        parts.append(f'<div class="dijitaliz-chat-row {side}"><div class="dijitaliz-bubble">{body_esc}')
        parts.append(f'<div class="dijitaliz-meta">{meta}</div></div></div>')
    parts.append("</div>")
    st.markdown("\n".join(parts), unsafe_allow_html=True)


def render_mobile_route_folium(route_df: pd.DataFrame, hours: int) -> None:
    """Son N saat rotası — Folium polyline + streamlit-folium."""
    if len(route_df) == 0:
        st.info("Rota için geçerli enlem/boylam içeren konum kaydı yok.")
        return
    try:
        import folium
        from streamlit_folium import st_folium
    except ImportError:
        st.warning("Çok noktalı rota haritası için: `pip install folium streamlit-folium`")
        st.map(route_df[["lat", "lon"]])
        return

    coords = list(zip(route_df["lat"].astype(float), route_df["lon"].astype(float)))
    mid_lat = float(route_df["lat"].mean())
    mid_lon = float(route_df["lon"].mean())
    m = folium.Map(location=(mid_lat, mid_lon), zoom_start=12, tiles="cartodb dark_matter")
    folium.PolyLine(
        coords,
        color="#00f0ff",
        weight=4,
        opacity=0.88,
        tooltip=f"Son ~{hours} saat — cihaz rotası",
    ).add_to(m)
    folium.CircleMarker(
        coords[0],
        radius=6,
        color="#ffd700",
        fill=True,
        fill_color="#ffd700",
        popup="Başlangıç (zaman sırası)",
    ).add_to(m)
    folium.CircleMarker(
        coords[-1],
        radius=7,
        color="#ff6b9d",
        fill=True,
        fill_color="#ff6b9d",
        popup="Bitiş (en son nokta)",
    ).add_to(m)
    st_folium(m, use_container_width=True, height=520)


def _diz_map_view_center(ip_df: pd.DataFrame, gps_df: pd.DataFrame) -> pdk.ViewState:
    lats: list[float] = []
    lons: list[float] = []
    if len(ip_df) > 0 and "lat" in ip_df.columns:
        lats.extend(ip_df["lat"].astype(float).tolist())
        lons.extend(ip_df["lon"].astype(float).tolist())
    if len(gps_df) > 0 and "lat" in gps_df.columns:
        lats.extend(gps_df["lat"].astype(float).tolist())
        lons.extend(gps_df["lon"].astype(float).tolist())
    if not lats:
        return pdk.ViewState(latitude=25, longitude=10, zoom=1.35, pitch=0)
    return pdk.ViewState(
        latitude=sum(lats) / len(lats),
        longitude=sum(lons) / len(lons),
        zoom=3.2 if len(lats) == 1 else 2.0,
        pitch=0,
    )


def make_diz_full_spectrum_map(ip_df: pd.DataFrame, gps_df: pd.DataFrame) -> pdk.Deck:
    """DİZ-Map: tehdit IP'leri (Zeek/Volatility) + mobil yedek son GPS izi."""
    layers: list[pdk.Layer] = []

    if len(ip_df) > 0:
        layers.append(
            pdk.Layer(
                "ScatterplotLayer",
                data=ip_df,
                get_position="[lon, lat]",
                get_fill_color=[0, 240, 255, 220],
                get_line_color=[255, 60, 120, 255],
                line_width_min_pixels=2,
                get_radius=180_000,
                pickable=True,
                auto_highlight=True,
                id="ip-threat",
            )
        )

    if len(gps_df) > 0:
        layers.append(
            pdk.Layer(
                "ScatterplotLayer",
                data=gps_df,
                get_position="[lon, lat]",
                get_fill_color=[255, 170, 0, 230],
                get_line_color=[255, 230, 120, 255],
                line_width_min_pixels=1,
                get_radius="radius",
                pickable=True,
                auto_highlight=True,
                id="mobile-gps",
            )
        )

    view = _diz_map_view_center(ip_df, gps_df)
    tooltip = {
        "html": "<b>{label}</b><br/><small>{tip_line2}</small>",
        "style": {"color": "white"},
    }
    return pdk.Deck(
        layers=layers,
        initial_view_state=view,
        map_style="dark",
        tooltip=tooltip,
    )


def lateral_movement_summary(cloud: dict[str, Any], mobile: dict[str, Any]) -> str:
    """Bulut → (ağ) → mobil yanal hareket hipotezi — tek ekran özeti."""
    lines: list[str] = []
    crit = cloud.get("critical_events") or []
    hybrid = cloud.get("hybrid_attacks") or []
    bulut_siz = cloud.get("bulut_sizintisi") or []
    stats_c = cloud.get("stats") or {}

    if stats_c.get("critical_events", 0) or crit:
        n = len(crit) if crit else stats_c.get("critical_events", 0)
        lines.append(f"**1. Bulut erişimi:** {n} kritik bulgu (ConsoleLogin, IAM, NSG, bucket silme vb.).")
    if bulut_siz:
        lines.append(
            f"**2. BULUT SIZINTISI:** {len(bulut_siz)} olay — bulut oturum IP’si **şüpheli** ağ listesinde (beaconing / DNS tünelleme)."
        )
    elif hybrid:
        lines.append(
            f"**2. Ağ köprüsü:** {len(hybrid)} **Hibrit** eşleşme — bulut IP’si genel PCAP/Zeek çıktısında (henüz şüpheli listesinde değil)."
        )
    elif crit:
        lines.append("**2. Ağ köprüsü:** Henüz eşleşme yok; PCAP analizi + `cloud_wrapper` korelasyonunu çalıştırın.")

    locs = mobile.get("locations") or []
    wa = mobile.get("whatsapp_messages") or []
    calls = mobile.get("call_logs") or []
    ct = mobile.get("contacts") or []
    br = mobile.get("browser_history") or []
    if locs or wa or calls or ct or br:
        lines.append(
            f"**3. Mobil yüzey:** {len(ct)} rehber, {len(br)} tarayıcı geçmişi, {len(wa)} WhatsApp, "
            f"{len(calls)} arama, {len(locs)} konum (SQLite + EXIF + harita önbelleği)."
        )
        lines.append(
            "**→ Lateral movement (hipotez):** Saldırgan önce bulut kimliğini veya konsolu ele geçirmiş; "
            "aynı tehdit aktörü kurbanın **mobil artefaktına** (mesaj / konum / arama) yansımış olabilir. "
            "Zaman sırası ve ortak IP / MFA telefonu ile doğrulayın."
        )
    elif crit or hybrid or bulut_siz:
        lines.append("**3. Mobil yüzey:** Henüz `mobile_findings.json` yok — `mobile_wrapper` ile yedek analizi ekleyin.")

    if not lines:
        return (
            "**DİZ-Full-Spectrum:** `cloud_findings.json` ve `mobile_findings.json` bulunamadı veya boş. "
            "`cloud_wrapper` ve `mobile_wrapper` çıktılarını `data/results/` altına koyun."
        )
    return "\n\n".join(lines)


def _iter_all_cloud_trace_events(cloud: dict[str, Any]) -> list[dict[str, Any]]:
    """Kritik + BULUT SIZINTISI + hibrit — Bulut İzleri paneli için düz liste."""
    out: list[dict[str, Any]] = []
    for key in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
        for e in cloud.get(key) or []:
            if isinstance(e, dict):
                out.append(e)
    return out


def _cloud_status_is_failure(status: str) -> bool:
    """Access Denied ve benzeri başarısızlık — saldırgan yetki denemesi süzgeci."""
    s = (status or "").lower()
    if not s.strip():
        return False
    needles = (
        "access denied",
        "accessdenied",
        "unauthorizedoperation",
        "unauthorized operation",
        "not authorized",
        "client.unauthorized",
        "forbidden",
        "explicit deny",
        "permission denied",
        "authorizationfailed",
        "authorization failed",
        "failure|",
        "failed",
        "is not authorized",
        "dryrunoperation",
    )
    return any(n in s for n in needles)


def build_cloud_traces_dataframe(cloud: dict[str, Any], failures_only: bool) -> pd.DataFrame:
    """Bulut İzleri: kimlik, IP, durum, aksiyon (filtre isteğe bağlı: yalnız hatalar)."""
    rows: list[dict[str, Any]] = []
    for e in _iter_all_cloud_trace_events(cloud):
        status = str(e.get("Status") or e.get("status_normalized") or "").strip()
        if failures_only and not _cloud_status_is_failure(status):
            continue
        user = (
            str(e.get("User_Identity") or e.get("privilege_summary") or e.get("user_arn") or "")
            .strip()
            or "Bilinmeyen kimlik"
        )
        sip = str(e.get("Source_IP") or e.get("source_ip") or "").strip()
        action = str(e.get("Action") or e.get("event_name") or e.get("operation_name") or "")
        prov = str(e.get("cloud", ""))
        ts = str(e.get("Timestamp") or e.get("event_time") or "")
        rows.append(
            {
                "cloud_user": user[:400],
                "source_ip": sip,
                "status": status[:300],
                "action": action[:300],
                "provider": prov,
                "timestamp": ts[:40],
            }
        )
    return pd.DataFrame(rows)


def build_cloud_users_bar_figure(df: pd.DataFrame, top_n: int = 22) -> go.Figure | None:
    """En çok işlem yapan bulut kimlikleri — yatay bar (Plotly)."""
    if df.empty or "cloud_user" not in df.columns:
        return None
    vc = df["cloud_user"].value_counts().head(top_n)
    if vc.empty:
        return None
    labels = [str(x)[:78] + ("…" if len(str(x)) > 78 else "") for x in vc.index]
    vals = vc.values.astype(int)
    fig = go.Figure(
        data=[
            go.Bar(
                x=vals,
                y=labels,
                orientation="h",
                marker=dict(
                    color=vals,
                    colorscale=[[0, "#1f3a5f"], [0.5, "#58a6ff"], [1, "#ffa657"]],
                    line=dict(color="rgba(0,240,255,0.35)", width=1),
                ),
                text=vals,
                textposition="outside",
                hovertemplate="%{y}<br>İşlem: %{x}<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        title=dict(
            text="Bulut İzleri · En yoğun Cloud User / kimlik (işlem adedi)",
            font=dict(size=17, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        plot_bgcolor="rgba(13,27,42,0.92)",
        font=dict(color="#e6edf3", family="Segoe UI, sans-serif"),
        xaxis=dict(title="Olay sayısı", gridcolor="rgba(80,100,120,0.35)"),
        yaxis=dict(title="", automargin=True, gridcolor="rgba(80,100,120,0.25)"),
        height=max(340, 56 + 28 * len(labels)),
        margin=dict(l=20, r=48, t=72, b=48),
    )
    return fig


def build_cloud_country_map_figure(
    df: pd.DataFrame,
    mask_sensitive: bool,
    max_ips_to_geo: int = 55,
) -> tuple[go.Figure | None, list[str]]:
    """
    Kaynak IP → ülke (ip-api.com); olay sayısına göre koropleth.
    """
    notes: list[str] = []
    if df.empty or "source_ip" not in df.columns:
        notes.append("Gösterilecek olay yok.")
        return None, notes

    raw_ips = [str(x).strip() for x in df["source_ip"].dropna().unique() if str(x).strip()]
    ips = [ip for ip in raw_ips if _is_plausible_ip(ip)]
    if not ips:
        notes.append("Coğrafya için genel (internet) kaynak IP yok veya tümü özel aralıkta / maskeli.")
        return None, notes

    if mask_sensitive:
        notes.append(
            "KVKK maskesi açık ve dosyada IP maskelenmiş olabilir; ham IP ile yeniden analiz önerilir."
        )

    ips = sorted(set(ips))[:max_ips_to_geo]
    if len(set(raw_ips)) > max_ips_to_geo:
        notes.append(f"Harita için en fazla {max_ips_to_geo} benzersiz IP coğrafi çözüldü (rate limit).")

    geo = _geolocate_ips_cached(tuple(ips))
    if not geo:
        notes.append("Konum servisi yanıt vermedi — ağ / güvenlik duvarı kontrol edin.")
        return None, notes

    counts = df.groupby("source_ip").size().reset_index(name="events")
    geo_df = pd.DataFrame(geo).merge(counts, left_on="ip", right_on="source_ip", how="left")
    geo_df["events"] = geo_df["events"].fillna(0).astype(int)

    country_agg = (
        geo_df.groupby(["country", "countryCode"], as_index=False)["events"]
        .sum()
        .query("countryCode != ''")
    )
    country_agg = country_agg[country_agg["countryCode"].astype(str).str.len() == 2]
    if country_agg.empty:
        notes.append("Ülke kodu eşlemesi yapılamadı.")
        return None, notes

    fig = px.choropleth(
        country_agg,
        locations="countryCode",
        locationmode="ISO-3166-1 alpha-2",
        color="events",
        hover_name="country",
        hover_data={"countryCode": True, "events": True},
        color_continuous_scale=["#0d1b2a", "#303d62", "#58a6ff", "#ffa657"],
    )
    fig.update_layout(
        title=dict(
            text="Bulut İzleri · İşlemlerin kaynak ülkeleri (IP → coğrafya)",
            font=dict(size=17, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        font=dict(color="#e6edf3", family="Segoe UI, sans-serif"),
        margin=dict(l=0, r=0, t=72, b=0),
        height=480,
        coloraxis_colorbar=dict(
            title=dict(text="Olay", font=dict(color="#e6edf3")),
            tickfont=dict(color="#e6edf3"),
        ),
    )
    fig.update_geos(
        bgcolor="rgba(10,22,40,0.98)",
        showframe=False,
        showcoastlines=True,
        projection_type="natural earth",
        coastlinecolor="rgba(80,120,160,0.5)",
    )
    return fig, notes


def _cloud_events_table_rows(cloud: dict[str, Any], max_rows: int = 80) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for e in (cloud.get("critical_events") or [])[:max_rows]:
        if not isinstance(e, dict):
            continue
        rows.append(
            {
                "provider": e.get("cloud", ""),
                "zaman": str(e.get("event_time", ""))[:32],
                "olay": str(e.get("event_name") or e.get("operation_name", ""))[:120],
                "yetki": str(e.get("privilege_summary", ""))[:160],
                "kaynak_IP": str(e.get("source_ip", "")),
                "BULUT_SIZ": "✓" if e.get("bulut_sizintisi") else "",
                "hibrit": "✓" if e.get("hybrid_attack") else "",
                "özet": str(e.get("raw_summary", ""))[:200],
            }
        )
    return pd.DataFrame(rows)


def _mobile_carving_highlights(mobile: dict[str, Any], max_rows: int = 25) -> pd.DataFrame:
    carved = [x for x in (mobile.get("carving_findings") or []) if isinstance(x, dict) and x.get("type") == "carved_jid_fragment"]
    rows = []
    for c in carved[:max_rows]:
        rows.append(
            {
                "offset": c.get("offset"),
                "guven": c.get("confidence"),
                "jid": str(c.get("jid_guess", ""))[:100],
                "onizleme": str(c.get("text_preview", ""))[:200],
                "db": str(c.get("source_db", ""))[-50:],
            }
        )
    return pd.DataFrame(rows)


def build_cloud_activity_heatmap_figure(cloud: dict[str, Any]) -> go.Figure | None:
    """
    AWS/Azure şüpheli aktivite yoğunluğu — olay adı × gün (Timesketch tarzı koyu tema).
    """
    rows: list[dict[str, Any]] = []
    bucket_meta = (
        ("critical_events", "kritik"),
        ("bulut_sizintisi", "BULUT_SIZ"),
        ("hybrid_attacks", "hibrit"),
    )
    for key, sev in bucket_meta:
        for e in cloud.get(key) or []:
            if not isinstance(e, dict):
                continue
            en = str(e.get("event_name") or e.get("operation_name") or "?")[:72]
            raw_t = str(e.get("event_time", ""))
            day = raw_t[:10] if len(raw_t) >= 10 else "tarih_bilinmiyor"
            prov = str(e.get("cloud", "?")).upper()[:6]
            rows.append({"event_name": f"{prov}:{en}", "day": day, "severity": sev})
    if not rows:
        return None
    df = pd.DataFrame(rows)
    top = df["event_name"].value_counts().head(20).index.tolist()
    df = df[df["event_name"].isin(top)]
    pivot = df.groupby(["event_name", "day"]).size().unstack(fill_value=0)
    if pivot.empty:
        return None
    pivot = pivot.sort_index(axis=0)
    pivot = pivot.reindex(sorted(pivot.columns), axis=1)
    z = pivot.values.tolist()
    x = [str(c) for c in pivot.columns]
    y = [str(i) for i in pivot.index]
    fig = go.Figure(
        data=go.Heatmap(
            z=z,
            x=x,
            y=y,
            colorscale=[
                [0.0, "#0a1628"],
                [0.35, "#1e3a5f"],
                [0.62, "#d29922"],
                [1.0, "#f85149"],
            ],
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Gün: %{x}<br>"
                "Olay sayısı: %{z}<extra></extra>"
            ),
            colorbar=dict(title="Adet", tickfont=dict(color="#e6edf3"), titlefont=dict(color="#e6edf3")),
        )
    )
    fig.update_layout(
        title=dict(
            text="DİZ-Global-View · Bulut şüpheli aktivite yoğunluğu (AWS / Azure)",
            font=dict(size=17, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        plot_bgcolor="rgba(13,27,42,0.92)",
        font=dict(color="#e6edf3", family="Segoe UI, 'IBM Plex Sans', sans-serif"),
        xaxis=dict(title="Tarih (gün)", gridcolor="rgba(80,100,120,0.35)", tickangle=-35),
        yaxis=dict(title="Sağlayıcı : olay / operasyon", gridcolor="rgba(80,100,120,0.35)"),
        height=max(400, min(780, 140 + 24 * len(y))),
        margin=dict(l=280, r=60, t=72, b=100),
    )
    return fig


def build_cloud_provider_hour_heatmap_figure(cloud: dict[str, Any]) -> go.Figure | None:
    """
    İkinci ısı haritası: bulut sağlayıcısı (AWS / Azure / diğer) × olayın gerçekleştiği saat (UTC, 0–23).
    Yoğunluğun gün içi dağılımını gösterir (operasyonel izleme).
    """
    rows: list[dict[str, str]] = []
    for key in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
        for e in cloud.get(key) or []:
            if not isinstance(e, dict):
                continue
            raw_t = str(e.get("event_time", "")).strip()
            hour_bucket = None
            if len(raw_t) >= 13:
                sep = raw_t[10] if len(raw_t) > 10 else ""
                if sep in ("T", " ", "t"):
                    try:
                        h = int(raw_t[11:13])
                        if 0 <= h <= 23:
                            hour_bucket = f"{h:02d}:00"
                    except ValueError:
                        pass
            if hour_bucket is None:
                continue
            cp = str(e.get("cloud", "") or "").strip().lower()
            if cp in ("aws", "amazon", "cloudtrail"):
                prov = "AWS"
            elif cp in ("azure", "microsoft", "arm"):
                prov = "Azure"
            else:
                prov = "Diğer / bilinmiyor"
            rows.append({"provider": prov, "hour": hour_bucket})
    if len(rows) < 2:
        return None
    df = pd.DataFrame(rows)
    hour_order = [f"{h:02d}:00" for h in range(24)]
    pivot = df.groupby(["provider", "hour"]).size().unstack(fill_value=0)
    pivot = pivot.reindex(columns=hour_order, fill_value=0)
    prov_order = ["AWS", "Azure", "Diğer / bilinmiyor"]
    idx = [p for p in prov_order if p in pivot.index] + [p for p in pivot.index if p not in prov_order]
    pivot = pivot.reindex(index=idx)
    if pivot.empty or pivot.shape[1] == 0:
        return None
    z = pivot.values.tolist()
    x = list(pivot.columns)
    y = [str(i) for i in pivot.index]
    fig = go.Figure(
        data=go.Heatmap(
            z=z,
            x=x,
            y=y,
            colorscale=[
                [0.0, "#0a1628"],
                [0.4, "#303d62"],
                [0.65, "#58a6ff"],
                [1.0, "#ffa657"],
            ],
            hovertemplate="%{y} · %{x}<br>Olay: %{z}<extra></extra>",
            colorbar=dict(title="Adet", tickfont=dict(color="#e6edf3"), titlefont=dict(color="#e6edf3")),
        )
    )
    fig.update_layout(
        title=dict(
            text="DİZ-Global-View · Sağlayıcı × saat (UTC) — gün içi aktivite yoğunluğu",
            font=dict(size=16, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        plot_bgcolor="rgba(13,27,42,0.92)",
        font=dict(color="#e6edf3", family="Segoe UI, sans-serif"),
        xaxis=dict(title="Saat (UTC)", tickangle=-45, gridcolor="rgba(80,100,120,0.35)"),
        yaxis=dict(title="Bulut sağlayıcısı", gridcolor="rgba(80,100,120,0.35)"),
        height=max(320, 100 + 48 * len(y)),
        margin=dict(l=200, r=50, t=64, b=76),
    )
    return fig


def build_whatsapp_traffic_sankey(mobile: dict[str, Any], max_jids: int = 28) -> go.Figure | None:
    """
    WhatsApp mesaj trafiği — merkez cihaz düğümü ↔ sohbet JID (UFED tarzı akış grafiği).
    """
    raw = mobile.get("whatsapp_messages") or []
    if len(raw) < 2:
        return None
    df = pd.DataFrame(raw[:12000])
    if "jid" not in df.columns:
        return None
    df["jid"] = df["jid"].astype(str).str[:80]
    df = df[df["jid"].str.len() > 3]
    if len(df) < 2:
        return None
    vc = df["jid"].value_counts()
    top_jids = list(vc.head(max_jids).index)
    df = df[df["jid"].isin(top_jids)]
    if "from_me" in df.columns:
        df["from_me"] = df["from_me"].fillna(False).astype(bool)
    else:
        df["from_me"] = False

    hub = "📱 Cihaz"
    labels = [hub] + top_jids
    ix = {lab: i for i, lab in enumerate(labels)}
    source, target, value = [], [], []
    for jid in top_jids:
        sub = df[df["jid"] == jid]
        out_n = int(sub["from_me"].sum())
        in_n = int(len(sub) - out_n)
        if out_n > 0:
            source.append(ix[hub])
            target.append(ix[jid])
            value.append(out_n)
        if in_n > 0:
            source.append(ix[jid])
            target.append(ix[hub])
            value.append(in_n)

    if not value or sum(value) == 0:
        return None

    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    label=labels,
                    pad=18,
                    thickness=22,
                    line=dict(color="rgba(0,240,255,0.35)", width=1),
                    color=[
                        "rgba(0,240,255,0.55)" if i == 0 else "rgba(230,237,243,0.18)"
                        for i in range(len(labels))
                    ],
                ),
                link=dict(
                    source=source,
                    target=target,
                    value=value,
                    hovertemplate="Mesaj hacmi: %{value}<extra></extra>",
                    color="rgba(210,153,34,0.35)",
                ),
            )
        ]
    )
    fig.update_layout(
        title=dict(
            text="DİZ-Global-View · WhatsApp mesaj trafiği (Sankey)",
            font=dict(size=17, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        font=dict(color="#e6edf3", family="Segoe UI, sans-serif"),
        height=520,
        margin=dict(l=40, r=40, t=72, b=40),
    )
    return fig


def build_whatsapp_networkx_graph_figure(
    mobile: dict[str, Any],
    max_nodes: int = 42,
    min_edge_weight: int = 1,
) -> go.Figure | None:
    """
    NetworkX: zaman sırasına göre ardışık farklı JID çiftleri = konuşma geçişi kenarı (ağırlık = geçiş sayısı).
    spring_layout + Plotly — tam graf görünümü.
    """
    try:
        import networkx as nx
    except ImportError:
        return None

    raw = mobile.get("whatsapp_messages") or []
    if len(raw) < 3:
        return None
    df = pd.DataFrame(raw[:18_000])
    if "jid" not in df.columns:
        return None
    df["jid"] = df["jid"].astype(str).str.strip().str[:72]
    df = df[df["jid"].str.len() > 3]
    if len(df) < 3:
        return None
    if "timestamp_iso" in df.columns:
        df["_ts"] = pd.to_datetime(df["timestamp_iso"], errors="coerce")
        df = df.sort_values("_ts", na_position="last")
    else:
        df = df.reset_index(drop=True)

    jids = df["jid"].tolist()
    G = nx.Graph()
    for i in range(len(jids) - 1):
        a, b = jids[i], jids[i + 1]
        if a == b:
            continue
        if G.has_edge(a, b):
            G[a][b]["weight"] = G[a][b].get("weight", 1) + 1
        else:
            G.add_edge(a, b, weight=1)

    if min_edge_weight > 1:
        thin = [(u, v) for u, v, d in G.edges(data=True) if d.get("weight", 1) < min_edge_weight]
        G.remove_edges_from(thin)
    G.remove_nodes_from(list(nx.isolates(G)))

    if G.number_of_nodes() == 0:
        return None

    deg_full = dict(G.degree())
    top = sorted(deg_full, key=lambda n: deg_full[n], reverse=True)[:max_nodes]
    G = nx.Graph(G.subgraph(top))
    G.remove_nodes_from(list(nx.isolates(G)))
    if G.number_of_nodes() == 0:
        return None

    deg = dict(G.degree())
    n_nodes = max(G.number_of_nodes(), 1)
    k = 2.0 / math.sqrt(n_nodes)
    pos = nx.spring_layout(G, k=k, iterations=60, seed=42, weight="weight")

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(color="rgba(120,165,210,0.5)", width=1.8),
        hoverinfo="none",
        showlegend=False,
    )

    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_deg = [deg[n] for n in G.nodes()]
    sizes = [10 + min(38, 3 * node_deg[i]) for i, n in enumerate(G.nodes())]
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        marker=dict(
            size=sizes,
            color=node_deg,
            colorscale=[[0, "#1f6feb"], [0.5, "#7ee787"], [1, "#f85149"]],
            line=dict(color="rgba(0,240,255,0.6)", width=1.2),
            showscale=True,
            colorbar=dict(
                title=dict(text="Derece", font=dict(color="#e6edf3")),
                tickfont=dict(color="#e6edf3"),
            ),
        ),
        text=[n[:52] + ("…" if len(n) > 52 else "") for n in G.nodes()],
        hovertemplate="<b>%{text}</b><br>Derece (kenar): %{marker.color}<extra></extra>",
        showlegend=False,
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=dict(
            text="DİZ-Global-View · WhatsApp tam graf (NetworkX · zaman sıralı JID geçişleri)",
            font=dict(size=16, color="#e6edf3"),
        ),
        template="plotly_dark",
        paper_bgcolor="rgba(10,22,40,0.98)",
        plot_bgcolor="rgba(7,14,24,0.95)",
        font=dict(color="#e6edf3"),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
        height=580,
        margin=dict(l=24, r=24, t=64, b=24),
        hovermode="closest",
    )
    return fig


def make_mobile_evidence_location_deck(ldf: pd.DataFrame) -> pdk.Deck | None:
    """Mobil kanıt konumları — pydeck (EXIF / SQLite / harita önbelleği)."""
    if len(ldf) == 0:
        return None
    dcf = ldf.copy()
    if "latitude" not in dcf.columns or "longitude" not in dcf.columns:
        return None
    dcf["lat"] = pd.to_numeric(dcf["latitude"], errors="coerce")
    dcf["lon"] = pd.to_numeric(dcf["longitude"], errors="coerce")
    dcf = dcf.dropna(subset=["lat", "lon"])
    dcf = dcf[(dcf["lat"].between(-90, 90)) & (dcf["lon"].between(-180, 180))]
    if len(dcf) == 0:
        return None
    if "source_type" in dcf.columns:
        dcf["kind"] = dcf["source_type"].astype(str).fillna("konum")
    else:
        dcf["kind"] = "konum"
    tbl = dcf["table"].astype(str).str[:32] if "table" in dcf.columns else pd.Series([""] * len(dcf))
    dcf["label"] = dcf["kind"] + " · " + tbl
    sp = dcf["source_path"].astype(str) if "source_path" in dcf.columns else pd.Series([""] * len(dcf))
    dcf["tip_small"] = sp.str[-70:]
    layer = pdk.Layer(
        "ScatterplotLayer",
        data=dcf,
        get_position="[lon, lat]",
        get_fill_color=[126, 231, 135, 220],
        get_line_color=[0, 240, 255, 255],
        line_width_min_pixels=2,
        get_radius=65000,
        pickable=True,
        auto_highlight=True,
    )
    center_lat = float(dcf["lat"].mean())
    center_lon = float(dcf["lon"].mean())
    zoom = 6.0 if len(dcf) < 4 else 4.5
    return pdk.Deck(
        layers=[layer],
        initial_view_state=pdk.ViewState(latitude=center_lat, longitude=center_lon, zoom=zoom, pitch=0),
        map_style="dark",
        tooltip={"html": "<b>{label}</b><br/><small>{tip_small}</small>", "style": {"color": "#e6edf3"}},
    )


def _path_to_nested_tree(paths: list[str]) -> dict:
    root: dict = {}
    for raw in paths:
        if not raw or len(raw) < 2:
            continue
        p = raw.replace("/", "\\")
        parts = [x for x in Path(p).parts if x]
        d = root
        for part in parts:
            if part not in d:
                d[part] = {}
            d = d[part]
    return root


def _render_tree_html(node: dict, depth: int = 0) -> str:
    if not node:
        return ""
    items = []
    for name in sorted(node.keys(), key=lambda x: (x.lower(), x)):
        child = node[name]
        pad = 14 + depth * 16
        if child:
            items.append(
                f'<details style="margin:4px 0;padding-left:{pad}px" open>'
                f"<summary style=\"cursor:pointer;color:#00f0ff;font-family:Share Tech Mono,monospace\">📁 {name}</summary>"
                f'<div style="border-left:1px solid #1e3a5f;margin-left:8px">{_render_tree_html(child, depth + 1)}</div>'
                f"</details>"
            )
        else:
            items.append(
                f'<div style="padding-left:{pad}px;color:#e6edf3;font-size:0.9rem;font-family:Share Tech Mono,monospace">📄 {name}</div>'
            )
    return "\n".join(items)


def collect_suspicious_file_paths() -> list[str]:
    """KAPE / Volatility / ağ ayıklama — şüpheli dosya yolları."""
    paths: list[str] = []

    net = _load_json(RESULTS / "network_analysis.json")
    if isinstance(net, dict):
        for sf in net.get("suspicious_files", []) or []:
            if isinstance(sf, dict):
                p = sf.get("extracted_path") or sf.get("filename") or sf.get("name") or ""
                if p:
                    paths.append(str(p))

    for name in ("windows_malfind.json", "windows_pslist.json", "windows_filescan.json"):
        raw = _load_json(RESULTS / "volatility" / name)
        for row in _flatten_vol_tree(raw):
            if not isinstance(row, dict):
                continue
            for key in ("Process", "process", "ImageFileName", "Image", "Name", "MappedPath", "Path"):
                v = row.get(key)
                if isinstance(v, str) and (":" in v or "\\" in v or "/" in v):
                    if any(v.lower().endswith(ext) for ext in SUSPICIOUS_EXT) or "malfind" in name.lower():
                        paths.append(v[:500])
                        break

    kape_roots = [RESULTS / "kape", RESULTS / "kape_output", RESULTS / "KAPE"]
    for kr in kape_roots:
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
    return uniq[:300]


def _normalize_severity(level: str) -> str:
    l = (level or "info").lower().strip()
    if l in ("critical", "crit"):
        return "critical"
    if l in ("high", "yüksek"):
        return "high"
    if l in ("medium", "orta"):
        return "medium"
    if l in ("low", "düşük"):
        return "low"
    return "info"


def _load_timeline_events() -> list[dict]:
    """Tüm kaynaklardan timeline olaylarını toplar."""
    events: list[dict] = []

    for p in [RESULTS / "hayabusa_output.json", RESULTS / "hayabusa.json"]:
        data = _load_json(p)
        if isinstance(data, list):
            for e in data:
                if isinstance(e, dict):
                    events.append({
                        "Timestamp": str(e.get("Timestamp") or e.get("timestamp") or "")[:19],
                        "Level": e.get("Level") or e.get("level") or "info",
                        "RuleTitle": e.get("RuleTitle") or e.get("Rule Title") or "",
                        "Details": str(e.get("Details") or e.get("details") or "")[:300],
                        "Source": "Hayabusa",
                    })
            break

    chainsaw = _load_json(RESULTS / "chainsaw_output.json")
    for e in chainsaw if isinstance(chainsaw, list) else []:
        if isinstance(e, dict):
            events.append({
                "Timestamp": str(e.get("Timestamp") or e.get("timestamp") or "")[:19],
                "Level": e.get("level") or e.get("Level") or "info",
                "RuleTitle": e.get("Rule Title") or e.get("RuleTitle") or "",
                "Details": str(e.get("Details") or e.get("EventData") or "")[:300],
                "Source": "Chainsaw",
            })

    net_path = RESULTS / "volatility" / "windows_netscan.json"
    if net_path.exists():
        data = _load_json(net_path)
        if isinstance(data, dict):
            rows = data.get("__children", [])
        elif isinstance(data, list):
            rows = data
        else:
            rows = []
        for r in rows:
            if isinstance(r, dict):
                events.append({
                    "Timestamp": str(r.get("CreateTime") or r.get("Timestamp") or "")[:19],
                    "Level": "info",
                    "RuleTitle": "NETWORK_MEMORY",
                    "Details": f"Local: {r.get('LocalAddress','')} -> Remote: {r.get('RemoteAddress','')}",
                    "Source": "Volatility",
                })

    net_data = _load_json(RESULTS / "network_analysis.json")
    if isinstance(net_data, dict):
        for e in net_data.get("http_traffic", net_data.get("http_requests", []))[:500]:
            if isinstance(e, dict):
                events.append({
                    "Timestamp": str(e.get("ts") or "")[:19],
                    "Level": "info",
                    "RuleTitle": "HTTP",
                    "Details": f"{e.get('method','')} {e.get('uri','')} -> {e.get('host','')}",
                    "Source": "Zeek",
                })
    for p in [RESULTS / "network" / "http_requests.json"]:
        if p.exists():
            for e in _load_json(p):
                if isinstance(e, dict):
                    events.append({
                        "Timestamp": str(e.get("ts") or "")[:19],
                        "Level": "info",
                        "RuleTitle": "HTTP",
                        "Details": f"{e.get('method','')} {e.get('uri','')} -> {e.get('host','')}",
                        "Source": "Zeek",
                    })
            break

    return events


def _load_triple_match_findings() -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Korelasyon: exfil, disk+RAM kesin, ATO, Tam-Saha (Full-Spectrum). Dosya veya canlı hesap."""
    exfil: list[dict] = []
    confirmed: list[dict] = []
    ato: list[dict] = []
    fs: list[dict] = []
    for path in [RESULTS / "exfiltration_findings.json", RESULTS / "correlation_results.json"]:
        if not path.exists():
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        exfil = data.get("exfiltration_threats", []) or []
        confirmed = data.get("confirmed_threats", []) or []
        ato = data.get("account_takeover_threats", []) or []
        fs = data.get("full_spectrum_threats", []) or []
        if exfil or confirmed or ato or fs:
            break
    if not exfil and not confirmed and not ato and not fs:
        try:
            events = _load_timeline_events()
            vol_results: dict = {}
            malfind_path = RESULTS / "volatility" / "windows_malfind.json"
            netscan_path = RESULTS / "volatility" / "windows_netscan.json"
            if malfind_path.exists() or netscan_path.exists():
                vol_results["results"] = {
                    "windows.malfind": _load_json(malfind_path),
                    "windows.netscan": _load_json(netscan_path),
                    "windows.pslist": _load_json(RESULTS / "volatility" / "windows_pslist.json"),
                }
            net_results = _load_json(RESULTS / "network_analysis.json")
            if not isinstance(net_results, dict):
                net_results = _load_json(RESULTS / "network" / "analysis_summary.json") or {}
            from core.correlator import (
                run_cloud_account_takeover_correlation,
                run_disk_memory_correlation,
                run_full_spectrum_correlation,
                run_triple_correlation,
            )

            _, exfil = run_triple_correlation(events, vol_results, net_results)
            _, confirmed = run_disk_memory_correlation(events, vol_results)
            cloud_payload = load_cloud_findings()
            _, ato = run_cloud_account_takeover_correlation(
                events,
                net_results,
                cloud_payload if cloud_payload else None,
            )
            mobile_payload = load_mobile_findings()
            _, fs = run_full_spectrum_correlation(
                events,
                net_results,
                cloud_payload if cloud_payload else None,
                mobile_payload if mobile_payload else None,
            )
        except Exception:
            pass
    return exfil, confirmed, ato, fs


def _apply_mask(events: list[dict], mask: bool) -> list[dict]:
    if not mask:
        return events
    try:
        from core.masking import mask_data

        return [
            {
                **e,
                "RuleTitle": mask_data(e.get("RuleTitle", "")),
                "Details": mask_data(e.get("Details", "")),
            }
            for e in events
        ]
    except ImportError:
        return events


def _dataframe_row_to_finding(row: Any) -> dict[str, Any]:
    """Plotly/tablo satırını analyst_notes parmak izi için dict yap."""
    ts_raw = row["Timestamp"]
    if hasattr(ts_raw, "strftime"):
        ts_s = ts_raw.strftime("%Y-%m-%d %H:%M:%S")
    else:
        ts_s = str(ts_raw)[:19]
    return {
        "Timestamp": ts_s[:19],
        "Level": str(row.get("Level", "") or ""),
        "Source": str(row.get("Source", "") or ""),
        "RuleTitle": str(row.get("RuleTitle", "") or ""),
        "Details": str(row.get("Details", "") or ""),
    }


def render_analyst_notebook(df_f: pd.DataFrame, mask_sensitive: bool) -> None:
    """
    Analist Not Defteri — Timesketch tarzı işbirlikli triyaj.
    Streamlit web'de sağ tık menüsü olmadığı için bulgu seçimi selectbox ile yapılır.
    """
    from core.analyst_notes import append_analyst_note, delete_note_at_index, load_notebook

    with st.expander("📓 Analist Not Defteri → HTML raporda «Uzman Görüşü»", expanded=False):
        st.caption(
            "Bulgu seçin ve triyaj notu ekleyin. Notlar `data/results/analyst_notebook.json` içinde saklanır; "
            "aşağıdaki «Analiz Raporunu İndir» çıktısında **Uzman Görüşü** bölümüne yazılır. "
            "(İşbirlikli inceleme modeli: Timesketch.)"
        )
        n_rows = len(df_f)
        if n_rows == 0:
            st.info("Not eklemek için önce zaman çizelgesinde görünen olay olmalı.")
            return

        idx_opts = list(range(n_rows))

        def _fmt_row(i: int) -> str:
            r = df_f.iloc[i]
            ts_raw = r["Timestamp"]
            if hasattr(ts_raw, "strftime"):
                ts_disp = ts_raw.strftime("%Y-%m-%d %H:%M")
            else:
                ts_disp = str(ts_raw)[:16]
            rt = str(r.get("RuleTitle", ""))[:46]
            return f"#{i + 1}  {ts_disp}  |  {r.get('Source', '')}  |  {rt}"

        choice = st.selectbox(
            "Bulgu seç (satır — sağ tık yerine)",
            idx_opts,
            format_func=_fmt_row,
            key="analyst_notebook_row_pick",
        )
        row = df_f.iloc[choice]
        finding = _dataframe_row_to_finding(row)
        prev = (
            f"{finding['Timestamp']} | {finding['Source']}\n{finding['RuleTitle']}\n"
            f"{finding['Details'][:500]}"
        )
        st.text_area("Seçili bulgu önizlemesi", prev, height=120, disabled=True, key="analyst_note_preview")
        comment = st.text_input("Ek yorum (isteğe bağlı)", "", key="analyst_note_comment")
        aname = st.text_input("Analist adı / baş harf (isteğe bağlı)", "", key="analyst_note_name")
        b1, b2, b3 = st.columns(3)
        if b1.button("Bu bir False Positive", key="analyst_btn_fp", use_container_width=True):
            append_analyst_note(
                finding,
                "false_positive",
                analyst_comment=comment,
                analyst_name=aname,
                mask_sensitive=mask_sensitive,
            )
            st.success("False Positive notu kaydedi. Raporu yeniden indirin.")
            st.rerun()
        if b2.button("Bu kritik bir sızma emaresi", key="analyst_btn_crit", use_container_width=True):
            append_analyst_note(
                finding,
                "critical_indicator",
                analyst_comment=comment,
                analyst_name=aname,
                mask_sensitive=mask_sensitive,
            )
            st.success("Kritik emare notu kaydedi. Raporu yeniden indirin.")
            st.rerun()
        if b3.button("Serbest analist notu", key="analyst_btn_free", use_container_width=True):
            append_analyst_note(
                finding,
                "analyst_note",
                analyst_comment=comment or "(Serbest not — yorum alanına metin girin)",
                analyst_name=aname,
                mask_sensitive=mask_sensitive,
            )
            st.success("Not kaydedi. Raporu yeniden indirin.")
            st.rerun()

        nb = load_notebook()
        notes = list(nb.get("notes") or [])
        if notes:
            st.markdown("##### Kayıtlı uzman notları")
            for i, n in enumerate(notes):
                snap = n.get("finding_snapshot") or {}
                lbl = n.get("label_tr", "")
                c1, c2 = st.columns([5, 1])
                with c1:
                    st.caption(f"{n.get('created_at', '')} — {lbl}")
                    st.write((snap.get("RuleTitle") or "")[:140])
                    if n.get("analyst_comment"):
                        st.caption(n.get("analyst_comment", "")[:400])
                with c2:
                    if st.button("Sil", key=f"analyst_del_{i}", help="Bu notu kaldır"):
                        delete_note_at_index(i)
                        st.rerun()


def _load_latest_diz_analyst_narrative() -> str:
    """`data/results/diz_analyst/*.md` — DİZ-Analist çıktısı (kaynak bulgular bölümü hariç)."""
    diz = RESULTS / "diz_analyst"
    if not diz.is_dir():
        return ""
    for name in ("detective_report.md", "attack_scenario.md"):
        p = diz / name
        if p.exists():
            raw = p.read_text(encoding="utf-8", errors="ignore")
            if "## Kaynak bulgular" in raw:
                raw = raw.split("## Kaynak bulgular")[0]
            return raw.strip()
    return ""


def _storyline_layer_key(source: str) -> str:
    s = (source or "").strip()
    if s == "Mobile":
        return "mobile"
    if s == "Cloud":
        return "cloud"
    if s == "Zeek":
        return "network"
    if s == "Volatility":
        return "ram"
    if s in ("Hayabusa", "Chainsaw"):
        return "disk"
    return "disk"


def _storyline_icon(layer: str) -> str:
    return {"mobile": "📱", "cloud": "☁️", "network": "🌐", "ram": "🧠", "disk": "💾"}.get(layer, "📌")


def _storyline_layer_label_tr(layer: str) -> str:
    return {
        "mobile": "Mobil kanıt",
        "cloud": "Bulut günlüğü",
        "network": "Ağ (PCAP/Zeek)",
        "ram": "RAM / Bellek",
        "disk": "Disk / EVTX",
    }.get(layer, "Olay")


def _cloud_rows_for_storyline(cloud: dict[str, Any], mask: bool, limit: int = 18) -> list[dict[str, Any]]:
    try:
        from core.masking import mask_data
    except ImportError:

        def mask_data(s: str, **_k: Any) -> str:  # type: ignore[misc]
            return str(s)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for bucket in ("bulut_sizintisi", "hybrid_attacks", "critical_events"):
        for e in cloud.get(bucket) or []:
            if len(rows) >= limit:
                return rows
            if not isinstance(e, dict):
                continue
            sig = f"{e.get('Action')}|{e.get('Timestamp')}|{e.get('event_name')}"
            if sig in seen:
                continue
            seen.add(sig)
            ts = str(e.get("Timestamp") or e.get("event_time") or e.get("time") or "")[:19]
            act = str(e.get("Action") or e.get("event_name") or "CloudTrail / Activity")[:140]
            uid = str(e.get("User_Identity") or e.get("user_arn") or e.get("privilege_summary") or "")
            sip = str(e.get("Source_IP") or e.get("source_ip") or "")
            det = f"{uid[:100]} · IP: {sip}".strip(" ·")
            if mask:
                act = mask_data(act)
                det = mask_data(det)
            rows.append(
                {
                    "Timestamp": ts,
                    "Level": "high" if e.get("critical") or bucket == "bulut_sizintisi" else "medium",
                    "RuleTitle": act,
                    "Details": (det or sip or act)[:420],
                    "Source": "Cloud",
                }
            )
    return rows


def _mobile_rows_for_storyline(mobile: dict[str, Any], mask: bool, limit: int = 12) -> list[dict[str, Any]]:
    try:
        from core.masking import mask_data
    except ImportError:

        def mask_data(s: str, **_k: Any) -> str:  # type: ignore[misc]
            return str(s)

    rows: list[dict[str, Any]] = []
    for w in mobile.get("whatsapp_messages") or []:
        if len(rows) >= limit:
            break
        if not isinstance(w, dict):
            continue
        ts = str(w.get("timestamp") or w.get("date") or w.get("time") or "")[:19]
        body = str(w.get("body") or w.get("text") or "")[:240]
        peer = str(w.get("remote_jid") or w.get("chat_jid") or w.get("chat") or "")
        if mask:
            body = mask_data(body)
            peer = mask_data(peer)
        rows.append(
            {
                "Timestamp": ts,
                "Level": "info",
                "RuleTitle": "Mobil · WhatsApp",
                "Details": f"{peer}: {body}".strip()[:420],
                "Source": "Mobile",
            }
        )
    for loc in mobile.get("locations") or []:
        if len(rows) >= limit:
            break
        if not isinstance(loc, dict):
            continue
        ts = str(loc.get("timestamp") or loc.get("time") or "")[:19]
        lat = loc.get("latitude") or loc.get("lat")
        lon = loc.get("longitude") or loc.get("lon")
        det = f"Konum · {lat}, {lon}"
        if mask:
            det = mask_data(det)
        rows.append(
            {
                "Timestamp": ts,
                "Level": "info",
                "RuleTitle": "Mobil · GPS / Konum",
                "Details": det[:420],
                "Source": "Mobile",
            }
        )
    return rows


def build_incident_storyline_events(
    base_events: list[dict[str, Any]],
    cloud: dict[str, Any],
    mobile: dict[str, Any],
    mask: bool,
    max_total: int = 100,
) -> list[dict[str, Any]]:
    extra = _cloud_rows_for_storyline(cloud, mask) + _mobile_rows_for_storyline(mobile, mask)
    merged = [dict(x) for x in base_events] + extra
    if not merged:
        return []
    df = pd.DataFrame(merged)
    df["_ts"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.sort_values("_ts", na_position="last")
    df = df.drop(columns=["_ts"])
    return df.head(max_total).to_dict("records")


_WORD_RE = re.compile(r"[\wğüşıöçĞÜŞİÖÇ]{3,}")


def _match_analyst_sentence(report: str, rule: str, details: str) -> str:
    """DİZ-Analist raporundan bu karta yakın cümleyi seç (kelime örtüşmesi)."""
    if not report or len(report) < 40:
        return ""
    body = report.replace("\r", "")
    chunks = re.split(r"(?<=[.!?])\s+|\n{2,}", body)
    words = set(_WORD_RE.findall(f"{rule} {details}".lower()))
    words = {w for w in words if len(w) > 2}
    if len(words) < 2:
        return ""
    best, sc = "", 0
    for chunk in chunks:
        chunk = chunk.strip()
        if len(chunk) < 28:
            continue
        if chunk.startswith("#"):
            continue
        sw = set(_WORD_RE.findall(chunk.lower()))
        inter = len(words & sw)
        if inter >= 2 and inter >= sc:
            sc = inter
            best = chunk
    if not best:
        return ""
    if len(best) > 360:
        return best[:357].rstrip() + "…"
    return best


def _storyline_fallback_blurb(layer: str, rule: str, level: str) -> str:
    r = (rule or "")[:72]
    lv = (level or "info").lower()
    if layer == "cloud":
        return (
            f"Analist özeti (şablon): Bulut kontrol düzleminde «{r}» kaydı hikâye zincirine eklenir; "
            "kimlik ve kaynak IP üzerinden lateral hareket veya yetki denemeleri değerlendirilmeli (Pathfinder olay örgüsü)."
        )
    if layer == "mobile":
        return (
            f"Analist özeti (şablon): Mobil yüzeyde «{r}» kanıtı zamana yayılır; cihaz içi iletişim veya konum, "
            "kurumsal sızıntı zamanı ile hizalanmalı (Timesketch anlatımı)."
        )
    if layer == "network":
        return (
            "Analist özeti (şablon): Ağ oturumu veya HTTP/DNS izi, dış haberleşme ve sızıntı adayları için "
            "disk olaylarıyla eşleştirilmeli."
        )
    if layer == "ram":
        if "high" in lv or "crit" in lv:
            return (
                "Analist özeti (şablon): Bellekten doğrulanan süreç/ağ göstergesi, aynı PID veya dış uç ile "
                "disk günlüklerinde aranmalı — muhtemel enjeksiyon veya kalıcılık emaresi."
            )
        return "Analist özeti (şablon): Bellek tabanlı ağ veya süreç izi, EVTx zaman çizelgesi ile çapraz kontrol edilmeli."
    if "privilege" in (rule or "").lower() or "admin" in (rule or "").lower():
        return f"Analist özeti (şablon): «{r}» olayı yetki yükseltme veya ayrıcalıklı oturum bağlamına işaret edebilir."
    return (
        f"Analist özeti (şablon): Disk kanalında «{r}» — olay örgüsünde başlangıç, yanal hareket veya sonuç fazına yerleştirin "
        "(MITRE / zaman kümesi ile)."
    )


def compute_kill_chain_status(
    events: list[dict[str, Any]],
    exfil_threats: list[Any],
    confirmed_threats: list[Any],
    ato_threats: list[Any],
    fs_threats: list[Any],
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Kill chain safhaları (Keşif → ... → Veri sızıntısı) — CrowdStrike Falcon / Sentinel pano mantığına yakın özet.
    """
    net = _load_json(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}

    parts: list[str] = []
    for e in events[:2500]:
        if not isinstance(e, dict):
            continue
        parts.append(str(e.get("RuleTitle", "")))
        parts.append(str(e.get("Details", "")))
    blob = " ".join(parts).lower()

    # 0 Keşif
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

    # 1 Sızma
    initial = bool(fs_threats)
    if not initial:
        for e in events:
            if not isinstance(e, dict):
                continue
            lv = str(e.get("Level", "")).lower()
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

    # 2 Yetki yükseltme
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

    # 3 Yayılma (yanal)
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
            if ob >= 50_000_000:  # yüksek çıkış hacmi — yanal / sızıntı adayı
                lateral = True
                break

    # 4 Veri sızıntısı
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

    labels = ["Keşif", "Sızma", "Yetki yükseltme", "Yayılma", "Veri sızıntısı"]
    detected = [recon, initial, priv, lateral, exfil]
    hit_indices = [i for i, d in enumerate(detected) if d]
    current_idx = max(hit_indices) if hit_indices else -1
    label_tr = labels[current_idx] if current_idx >= 0 else "Henüz teyit yok (analiz bekleniyor)"

    return {
        "labels": labels,
        "detected": detected,
        "current_index": current_idx,
        "current_label_tr": label_tr,
        "hit_count": sum(1 for d in detected if d),
    }


def render_kill_chain_status_bar(
    events: list[dict[str, Any]],
    exfil_threats: list[Any],
    confirmed_threats: list[Any],
    ato_threats: list[Any],
    fs_threats: list[Any],
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> None:
    kc = compute_kill_chain_status(
        events, exfil_threats, confirmed_threats, ato_threats, fs_threats, cloud_payload, mobile_payload
    )
    labels = kc["labels"]
    detected = kc["detected"]
    cur = kc["current_index"]
    cur_lbl = kc["current_label_tr"]

    steps_html: list[str] = []
    n = len(labels)
    for i, lbl in enumerate(labels):
        done = bool(detected[i])
        is_current = cur == i
        is_past = cur > i
        cls = ["kc-step"]
        if done:
            cls.append("kc-done")
        if is_current:
            cls.append("kc-current")
        if is_past and not done:
            cls.append("kc-implied")
        mark = "✓" if done else ("◉" if is_current and cur >= 0 else "○")
        steps_html.append(
            f'<div class="{" ".join(cls)}" title="{html.escape(lbl)}">'
            f'<span class="kc-mark">{mark}</span>'
            f'<span class="kc-name">{html.escape(lbl)}</span>'
            f"</div>"
        )
        if i < n - 1:
            line_on = (cur > i) or (cur == i and done)
            lcls = "kc-connector" + (" kc-connector-on" if line_on else "")
            steps_html.append(f'<div class="{lcls}"></div>')

    foot = (
        f"Şu an vurgulanan safha: <strong>{html.escape(cur_lbl)}</strong> · "
        f"Tespit edilen adım: <strong>{kc['hit_count']}</strong>/5. "
        "Otomatik sınıflandırma — Falcon / Sentinel panellerindeki gibi triyaj öncesi özet kabul edin."
    )

    block = f"""
<div class="kc-bar-wrap">
  <div class="kc-bar-head">
    <span class="kc-bar-title">Saldırı safhası</span>
    <span class="kc-bar-sub">Kill Chain durumu · CrowdStrike Falcon & Microsoft Sentinel olay özeti disiplini</span>
  </div>
  <div class="kc-steps-row">{"".join(steps_html)}</div>
  <div class="kc-bar-foot">{foot}</div>
</div>
"""
    st.markdown(block, unsafe_allow_html=True)


def render_incident_storyline(
    base_events: list[dict[str, Any]],
    mask_sensitive: bool,
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> None:
    """
    Dikey Incident Storyline — Pathfinder olay örgüsü + Timesketch storytelling.
    """
    narrative = _load_latest_diz_analyst_narrative()
    storyline_events = build_incident_storyline_events(
        base_events, cloud_payload, mobile_payload, mask_sensitive, max_total=100
    )
    st.markdown("### 📖 Olay Hikayesi — Incident Storyline")
    st.caption(
        "Cellebrite Pathfinder tarzı **olay örgüsü** ve Timesketch **Storytelling**: sol dikey eksen üzerinde "
        "kanıt kartları. **Analist Özeti** — `core/ai_analyst.py` çıktısından cümle eşlemesi veya otomatik şablondur "
        "(LLM raporu: `data/results/diz_analyst/`)."
    )
    if not storyline_events:
        st.info("Hikâye akışı için olay yok. Önce `main.py` veya modüllerle `data/results` doldurun.")
        return

    if narrative:
        st.caption(f"DİZ-Analist metni yüklendi (~{len(narrative)} karakter); kart altında eşleşen cümle gösterilir.")
    else:
        st.caption("DİZ-Analist raporu bulunamadı — `python main.py ... --ai-detective` veya `--diz-ai` ile üretin; şimdilik şablon özet kullanılıyor.")

    blocks: list[str] = []
    for ev in storyline_events:
        layer = _storyline_layer_key(str(ev.get("Source", "")))
        icon = _storyline_icon(layer)
        layer_tr = _storyline_layer_label_tr(layer)
        rt = str(ev.get("RuleTitle", ""))
        dt = str(ev.get("Details", ""))
        ts_disp = str(ev.get("Timestamp", ""))[:19] or "— (zaman damgası yok)"
        lvl = str(ev.get("Level", ""))
        matched = _match_analyst_sentence(narrative, rt, dt)
        if not matched:
            matched = _storyline_fallback_blurb(layer, rt, lvl)
        rt_e = html.escape(rt[:200])
        dt_e = html.escape(dt[:450])
        ts_e = html.escape(ts_disp)
        lvl_e = html.escape(lvl[:24])
        sum_e = html.escape(matched)

        blocks.append(
            f"""
<div class="storyline-item">
  <div class="storyline-glyph" title="{html.escape(layer_tr)}">{icon}</div>
  <div class="storyline-card">
    <div class="storyline-meta"><strong style="color:#58a6ff;">{html.escape(layer_tr)}</strong> · {ts_e} · <span style="color:#8b949e;">{lvl_e}</span></div>
    <h4>{rt_e}</h4>
    <div class="storyline-body">{dt_e}</div>
    <div class="storyline-ai"><strong>Analist özeti:</strong> {sum_e}</div>
  </div>
</div>"""
        )

    shell = (
        '<div class="storyline-shell">'
        + "".join(blocks)
        + "</div>"
    )
    st.markdown(shell, unsafe_allow_html=True)


def _relationship_pick_hub_ip(net: dict[str, Any], mask_sensitive: bool) -> str | None:
    """Şüpheli dış IP — threat map ile uyumlu (maskeli dosyada ham IP yoksa None)."""
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
                ip = m.group(0)
                if _is_plausible_ip(ip) and ip in bucket:
                    return ip
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


def build_relationship_graph_figure(
    mask_sensitive: bool,
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> tuple[go.Figure | None, list[str]]:
    """
    Maltego tarzı yönlü ilişki grafiği + Arkime oturum düğümleri.
    Merkez: saldırgan IP veya şüpheli bulut kullanıcısı.
    """
    try:
        import networkx as nx
    except ImportError:
        return None, ["İlişki grafiği için: pip install networkx"]

    notes: list[str] = []
    net = _load_json(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}

    hub_ip = _relationship_pick_hub_ip(net, mask_sensitive)
    hub_user = _relationship_pick_hub_user(cloud_payload) if not hub_ip else None

    if not hub_ip and not hub_user:
        notes.append(
            "Grafik merkezi için şüpheli dış IP (Zeek/PCAP) veya `cloud_findings.json` içinde kimlik gerekir. "
            "KVKK maskesi açıksa ham IP grafiğe taşınmaz."
        )
        return None, notes

    G = nx.DiGraph()
    hub_id = "__HUB__"
    if hub_ip:
        G.add_node(
            hub_id,
            label=f"Saldırgan / şüpheli IP\n{hub_ip}",
            ntype="hub_ip",
            hover=f"Merkez uç nokta: {hub_ip}",
        )
    else:
        udisp = hub_user or "—"
        G.add_node(
            hub_id,
            label=f"Şüpheli kullanıcı\n{udisp[:72]}{'…' if len(udisp) > 72 else ''}",
            ntype="hub_user",
            hover=udisp[:300],
        )

    try:
        from core.masking import mask_data
    except ImportError:

        def mask_data(s: str, **_k: Any) -> str:  # type: ignore[misc]
            return str(s)

    # — Dosyalar
    paths = collect_suspicious_file_paths()
    for i, p in enumerate(paths[:8]):
        base = Path(p).name
        if len(base) > 46:
            base = base[:43] + "…"
        hover_p = mask_data(p[:400]) if mask_sensitive else p[:400]
        nid = f"f{i}"
        G.add_node(nid, label=f"📄 {base}", ntype="file", hover=hover_p)
        G.add_edge(
            hub_id,
            nid,
            label="Ağ trafiği / oturum ile ilişkili dosya (ayıklama veya disk izi)",
        )

    # — Ağ oturumları (Arkime derinliği)
    if hub_ip:
        n_ec = 0
        for conn in net.get("connections") or []:
            if n_ec >= 7 or not isinstance(conn, dict):
                break
            oh = str(conn.get("id.orig_h") or conn.get("orig_h") or "")
            rh = str(conn.get("id.resp_h") or conn.get("resp_h") or "")
            rp = str(conn.get("id.resp_p") or conn.get("resp_p") or "?")
            if oh == hub_ip or rh == hub_ip:
                nid = f"net{n_ec}"
                G.add_node(nid, label=f"🌐 TCP/UDP :{rp}", ntype="net", hover=json.dumps(conn, ensure_ascii=False)[:220])
                G.add_edge(
                    hub_id,
                    nid,
                    label="Ağ trafiği üzerinden dış uç / oturum (Zeek conn — Arkime benzeri)",
                )
                n_ec += 1
        if n_ec == 0 and (net.get("http_traffic") or net.get("http_requests")):
            G.add_node("n_http", label="🌐 HTTP / uygulama trafiği", ntype="net", hover="HTTP log özeti")
            G.add_edge(hub_id, "n_http", label="Uygulama katmanında sızdırma veya API iletişimi adayı")
    else:
        G.add_node("n_api", label="🌐 Bulut & oturum yüzeyi", ntype="net", hover="IAM / Console")
        G.add_edge(hub_id, "n_api", label="Kimlik kökü — CloudTrail / Activity üzerinden ilişkiler")

    # — Bellek (Volatility netscan)
    ns_raw = _load_json(RESULTS / "volatility" / "windows_netscan.json")
    for r in _flatten_vol_tree(ns_raw)[:50]:
        if not isinstance(r, dict):
            continue
        rem = str(r.get("RemoteAddress") or r.get("remote_address") or "")
        if hub_ip and hub_ip in rem:
            if "mem_ns" not in G:
                G.add_node("mem_ns", label="🧠 Bellek (netscan)", ntype="memory", hover=rem[:200])
                G.add_edge(
                    hub_id,
                    "mem_ns",
                    label="Bellekte soket olarak tespit edildi — Volatility netscan",
                )
            break

    # — Mobil mesajlar
    wlist = mobile_payload.get("whatsapp_messages") or []
    if isinstance(wlist, list) and len(wlist) > 0:
        G.add_node("mob_wa", label=f"📱 Mobil · WhatsApp ({len(wlist)})", ntype="mobile", hover="msgstore kanıtı")
        G.add_edge(
            hub_id,
            "mob_wa",
            label="Mobil mesajlar — aynı vaka örgüsünde (cihaz içi iletişim)",
        )

    # — Bulut (aynı kaynak IP)
    if hub_ip:
        hit_cloud = False
        for bucket in ("bulut_sizintisi", "hybrid_attacks", "critical_events"):
            for e in cloud_payload.get(bucket) or []:
                if not isinstance(e, dict):
                    continue
                sip = str(e.get("Source_IP") or e.get("source_ip") or "")
                if sip == hub_ip or (hub_ip in sip):
                    hit_cloud = True
                    break
            if hit_cloud:
                break
        if hit_cloud and "cld_hub" not in G:
            G.add_node("cld_hub", label="☁️ CloudTrail / IAM", ntype="cloud", hover="Bulut günlüğü")
            G.add_edge(
                hub_id,
                "cld_hub",
                label="Bulut oturumu bu IP ile hizalanıyor — yetki / ATO adayı",
            )

    if G.number_of_nodes() <= 1:
        notes.append("Merkez dışında düğüm oluşturulamadı; dosya, PCAP veya mobil çıktısı ekleyin.")
        return None, notes

    pos = nx.spring_layout(G, k=2.4, iterations=100, seed=44)
    hx, hy = pos[hub_id]
    for n in pos:
        pos[n] = (float(pos[n][0]) - hx, float(pos[n][1]) - hy)

    nodes_order = list(G.nodes())
    node_x = [pos[n][0] for n in nodes_order]
    node_y = [pos[n][1] for n in nodes_order]
    node_labels = [G.nodes[n].get("label", n) for n in nodes_order]
    hover_tx = [G.nodes[n].get("hover", str(n)) for n in nodes_order]

    color_map = {
        "hub_ip": "#f85149",
        "hub_user": "#c084fc",
        "file": "#58a6ff",
        "net": "#00d4aa",
        "memory": "#7ee787",
        "mobile": "#f0b429",
        "cloud": "#a78bfa",
    }
    size_map = {"hub_ip": 36, "hub_user": 36, "file": 20, "net": 22, "memory": 24, "mobile": 26, "cloud": 24}
    node_color = [color_map.get(G.nodes[n].get("ntype", ""), "#8b949e") for n in nodes_order]
    node_size = [size_map.get(G.nodes[n].get("ntype", ""), 20) for n in nodes_order]

    annos: list[dict[str, Any]] = []
    for u, v, d in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        annos.append(
            {
                "x": x1,
                "y": y1,
                "ax": x0,
                "ay": y0,
                "xref": "x",
                "yref": "y",
                "axref": "x",
                "ayref": "y",
                "showarrow": True,
                "arrowhead": 2,
                "arrowsize": 1.25,
                "arrowwidth": 2,
                "arrowcolor": "rgba(0,240,255,0.5)",
                "text": "",
            }
        )
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        annos.append(
            {
                "x": mx,
                "y": my,
                "text": str(d.get("label", ""))[:100],
                "showarrow": False,
                "font": {"size": 9, "color": "#f0e6ff"},
                "bgcolor": "rgba(17,29,46,0.9)",
                "bordercolor": "rgba(88,166,255,0.45)",
                "borderpad": 4,
            }
        )

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            marker=dict(size=node_size, color=node_color, line=dict(width=2, color="rgba(255,255,255,0.65)")),
            text=node_labels,
            textposition="top center",
            textfont=dict(size=11, color="#e6edf3", family="Segoe UI, sans-serif"),
            hovertext=hover_tx,
            hoverinfo="text",
        )
    )
    fig.update_layout(
        title=dict(
            text="İlişki grafiği — merkez uç nokta ve kanıt örgüsü (Maltego / Arkime hedefi)",
            font=dict(color="#e6edf3", size=15),
        ),
        xaxis=dict(visible=False, range=[-2.1, 2.1], fixedrange=True),
        yaxis=dict(visible=False, range=[-2.1, 2.1], scaleanchor="x", scaleratio=1, fixedrange=True),
        plot_bgcolor="#0a1628",
        paper_bgcolor="#050810",
        height=640,
        showlegend=False,
        margin=dict(l=24, r=24, t=56, b=24),
        annotations=annos,
    )
    notes.append("Ok üzerindeki kutular bağlam notudur (otomatik üretim — manuel doğrulama önerilir).")
    return fig, notes


def render_relationship_graph_view(
    mask_sensitive: bool,
    cloud_payload: dict[str, Any],
    mobile_payload: dict[str, Any],
) -> None:
    st.markdown("### 🕸️ İlişki Grafiği (Graph View)")
    st.caption(
        "**Maltego** bağlantı analizi ve **Arkime** oturum görselleştirmesi hedefi: merkezde saldırgan IP veya şüpheli kullanıcı; "
        "çevrede dosya, ağ, bellek ve mobil düğümler; ok üzerinde bağlamsal açıklama."
    )
    fig, gnotes = build_relationship_graph_figure(mask_sensitive, cloud_payload, mobile_payload)
    for n in gnotes:
        st.caption(n)
    if fig is not None:
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info(
            "Grafiği üretmek için: `main.py -p` (PCAP), Volatility netscan, `cloud_findings.json`, mobil yedek veya "
            "ayıklanan dosya çıktıları ekleyin. Maskeli modda IP maskelenmişse merkez IP kullanılamaz."
        )


def main() -> None:
    st.set_page_config(
        page_title="DİZ — Siber Savaş Odası",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@500;700&display=swap" rel="stylesheet">
    <style>
    .war-wrap {
        background: radial-gradient(ellipse at top, #0d1b2a 0%, #050810 55%, #020408 100%);
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 0 40px rgba(0, 240, 255, 0.08), inset 0 1px 0 rgba(255,255,255,0.05);
    }
    .war-title {
        font-family: 'Orbitron', sans-serif;
        font-weight: 700;
        font-size: 1.75rem;
        letter-spacing: 0.12em;
        color: #e6edf3;
        text-shadow: 0 0 20px rgba(0, 240, 255, 0.45);
        margin: 0 0 0.35rem 0;
    }
    .war-sub {
        font-family: 'Share Tech Mono', monospace;
        color: #7ee787;
        font-size: 0.9rem;
        opacity: 0.95;
        margin: 0;
    }
    .critical-alert {
        background: linear-gradient(135deg, #3d0a0a, #5c1010);
        color: #fff;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin: 1rem 0;
        border-left: 6px solid #f85149;
        font-weight: 600;
        box-shadow: 0 4px 24px rgba(248,81,73,0.25);
    }
    .critical-alert h4 { margin: 0 0 0.5rem 0; color: #fecaca; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] { padding: 10px 20px; font-weight: 600; }
    div[data-testid="stSidebar"] { background: linear-gradient(180deg, #0a1628 0%, #050810 100%); }
    .storyline-shell {
        position: relative;
        margin: 0.5rem 0 1.75rem 12px;
        padding: 4px 0 6px 0;
        border-left: 3px solid rgba(0, 240, 255, 0.42);
    }
    .storyline-item {
        position: relative;
        margin: 0 0 1.35rem 0;
        padding-left: 42px;
        min-height: 56px;
    }
    .storyline-glyph {
        position: absolute;
        left: -23px;
        top: 10px;
        width: 34px;
        height: 34px;
        border-radius: 50%;
        background: #0d1b2a;
        border: 2px solid #00f0ff;
        box-shadow: 0 0 14px rgba(0, 240, 255, 0.28);
        font-size: 15px;
        line-height: 30px;
        text-align: center;
        z-index: 2;
    }
    .storyline-card {
        background: linear-gradient(165deg, #111d2e 0%, #0d1520 100%);
        border: 1px solid #1e3a5f;
        border-radius: 10px;
        padding: 12px 14px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.35);
    }
    .storyline-card h4 {
        margin: 0 0 6px 0;
        font-size: 0.95rem;
        color: #e6edf3;
        font-weight: 600;
    }
    .storyline-meta {
        font-size: 0.72rem;
        color: #8b949e;
        margin-bottom: 8px;
    }
    .storyline-body {
        font-size: 0.82rem;
        color: #c9d1d9;
        line-height: 1.45;
    }
    .storyline-ai {
        margin-top: 10px;
        padding: 9px 11px;
        border-radius: 8px;
        background: rgba(168, 85, 247, 0.11);
        border-left: 3px solid #a855f7;
        font-size: 0.78rem;
        color: #e9d5ff;
        line-height: 1.45;
    }
    .storyline-ai strong { color: #c4b5fd; }
    /* Kill Chain bar — Sentinel / Falcon olay üst özeti */
    .kc-bar-wrap {
        background: linear-gradient(180deg, #0f1724 0%, #0a1019 100%);
        border: 1px solid rgba(0, 188, 242, 0.28);
        border-radius: 10px;
        padding: 14px 18px 12px 18px;
        margin: 0 0 1rem 0;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255,255,255,0.04);
    }
    .kc-bar-head {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        gap: 10px 16px;
        margin-bottom: 12px;
        border-bottom: 1px solid rgba(100, 116, 139, 0.35);
        padding-bottom: 10px;
    }
    .kc-bar-title {
        font-family: 'Segoe UI', system-ui, sans-serif;
        font-weight: 700;
        font-size: 0.95rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #e2e8f0;
    }
    .kc-bar-sub {
        font-size: 0.72rem;
        color: #94a3b8;
        font-weight: 500;
    }
    .kc-steps-row {
        display: flex;
        flex-wrap: wrap;
        align-items: stretch;
        justify-content: space-between;
        gap: 6px 4px;
        margin-bottom: 8px;
    }
    .kc-step {
        flex: 1 1 90px;
        min-width: 72px;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
        padding: 10px 6px 8px;
        border-radius: 8px;
        background: rgba(15, 23, 42, 0.65);
        border: 1px solid rgba(71, 85, 105, 0.5);
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    .kc-step.kc-done {
        border-color: rgba(16, 185, 129, 0.55);
        background: rgba(6, 78, 59, 0.2);
    }
    .kc-step.kc-current {
        border-color: rgba(0, 188, 242, 0.95);
        box-shadow: 0 0 0 1px rgba(0, 188, 242, 0.35), 0 0 22px rgba(0, 188, 242, 0.22);
        animation: kc-pulse 2.2s ease-in-out infinite;
    }
    .kc-step.kc-implied {
        border-style: dashed;
        opacity: 0.88;
    }
    @keyframes kc-pulse {
        0%, 100% { box-shadow: 0 0 0 1px rgba(0, 188, 242, 0.35), 0 0 18px rgba(0, 188, 242, 0.18); }
        50% { box-shadow: 0 0 0 2px rgba(0, 188, 242, 0.5), 0 0 28px rgba(0, 188, 242, 0.28); }
    }
    .kc-mark {
        font-size: 1.05rem;
        line-height: 1.2;
        margin-bottom: 4px;
        color: #64748b;
    }
    .kc-done .kc-mark { color: #34d399; font-weight: 700; }
    .kc-current .kc-mark { color: #00bcf2; }
    .kc-name {
        font-size: 0.68rem;
        font-weight: 600;
        color: #cbd5e1;
        line-height: 1.25;
    }
    .kc-done .kc-name { color: #ecfdf5; }
    .kc-current .kc-name { color: #e0f7ff; font-weight: 700; }
    .kc-connector {
        flex: 0 0 16px;
        align-self: center;
        height: 3px;
        margin-top: -24px;
        background: rgba(51, 65, 85, 0.75);
        border-radius: 2px;
        min-width: 8px;
    }
    .kc-connector-on {
        background: linear-gradient(90deg, #059669, #00bcf2);
        box-shadow: 0 0 8px rgba(0, 188, 242, 0.35);
    }
    .kc-bar-foot {
        font-size: 0.72rem;
        color: #94a3b8;
        line-height: 1.45;
        padding-top: 6px;
    }
    .kc-bar-foot strong { color: #e2e8f0; }
    </style>
    """,
        unsafe_allow_html=True,
    )

    st.sidebar.markdown("### 🔒 KVKK")
    mask_sensitive = st.sidebar.toggle("Maskeli görüntüle", value=True)
    st.sidebar.caption("Tehdit haritası için ham IP gerekir; maskeli modda harita devre dışı kalabilir.")

    events = _load_timeline_events()
    events = _apply_mask(events, mask_sensitive)
    exfil_threats, confirmed_threats, ato_threats, fs_threats = _load_triple_match_findings()
    cloud_payload = load_cloud_findings()
    mobile_payload = load_mobile_findings()

    st.markdown(
        """
    <div class="war-wrap">
        <p class="war-title">SİBER SAVAŞ ODASI</p>
        <p class="war-sub">DİZ-Full-Spectrum · Bulut + Kurumsal ağ + Mobil · Tek ekranda lateral movement</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    render_kill_chain_status_bar(
        events, exfil_threats, confirmed_threats, ato_threats, fs_threats, cloud_payload, mobile_payload
    )
    render_incident_storyline(events, mask_sensitive, cloud_payload, mobile_payload)
    render_relationship_graph_view(mask_sensitive, cloud_payload, mobile_payload)

    if exfil_threats or confirmed_threats or ato_threats or fs_threats:
        st.markdown("### 🚨 Kritik Uyarı Paneli")
        for fs in fs_threats:
            st.markdown(
                f"""
            <div class="critical-alert" style="border-left-color:#f87171;background:linear-gradient(135deg,#450a0a,#1e293b);">
            <h4>⚔ TOPYEKÜN SİBER SALDIRI (Tam-Saha-Pres)</h4>
            {fs.get('technical_summary', fs.get('details', ''))}
            </div>
            """,
                unsafe_allow_html=True,
            )
        for at in ato_threats:
            st.markdown(
                f"""
            <div class="critical-alert" style="border-left-color:#a855f7;background:linear-gradient(135deg,#3b0764,#581c87);">
            <h4>🛡 BULUT HESABI ELE GEÇİRME (Account Takeover)</h4>
            {at.get('technical_summary', at.get('details', ''))}
            </div>
            """,
                unsafe_allow_html=True,
            )
        for et in exfil_threats:
            st.markdown(
                f"""
            <div class="critical-alert">
            <h4>⚠ KRİTİK VERİ SIZINTISI (Üçlü Eşleşme)</h4>
            {et.get('technical_summary', et.get('details', ''))}
            </div>
            """,
                unsafe_allow_html=True,
            )
        for ct in confirmed_threats[:3]:
            st.markdown(
                f"""
            <div class="critical-alert">
            <h4>⚠ KESİNLEŞMİŞ TEHDİT (Disk + RAM)</h4>
            {ct.get('rule_title', '')} — {ct.get('details', '')[:150]}
            </div>
            """,
                unsafe_allow_html=True,
            )

    # --- DİZ-Map: IP + mobil GPS ---
    st.markdown("### 🛰️ DİZ-Map (Full-Spectrum)")
    st.caption(
        "Tehdit IP’leri (Zeek/Volatility · ip-api.com) + mobil yedekten zaman sırasına göre son GPS noktaları — tek harita"
    )

    map_df, map_notes = build_threat_map_data(mask_sensitive)
    for n in map_notes:
        st.caption(n)

    gps_df = build_mobile_gps_map_df(mobile_payload)

    if len(map_df) > 0 or len(gps_df) > 0:
        deck = make_diz_full_spectrum_map(map_df, gps_df)
        st.pydeck_chart(deck, use_container_width=True, height=460)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Haritadaki IP", str(len(map_df)) if len(map_df) else "0")
        m2.metric("Ülke (IP)", str(map_df["country"].nunique()) if len(map_df) else "—")
        m3.metric("Mobil GPS (iz N)", str(len(gps_df)) if len(gps_df) else "0")
        bs_n = len(cloud_payload.get("bulut_sizintisi") or [])
        m4.metric("BULUT SIZINTISI", str(bs_n) if bs_n else "0")
    else:
        st.info(
            "Harita için en az biri gerekir: dış IP (PCAP + `main.py -p`) veya `mobile_findings.json` içinde konum."
        )

    st.markdown("### 🎯 DİZ-Full-Spectrum — Lateral movement")
    st.markdown(lateral_movement_summary(cloud_payload, mobile_payload))

    st.markdown(
        """
        <div style="background:linear-gradient(90deg,rgba(0,240,255,0.08),transparent);border-left:4px solid #00f0ff;
        padding:0.75rem 1rem;border-radius:6px;margin:1rem 0 0.5rem 0;">
        <strong style="color:#e6edf3;font-size:1.05rem;">DİZ-Global-View</strong>
        <span style="color:#8b949e;font-size:0.9rem;"> — Timesketch düzeyinde özet görünüm · UFED derinliğinde teknik detay</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_cloud, tab_cloud_traces, tab_mobile, tab_mobile_lab = st.tabs(
        ["☁️ Bulut Analizi", "☁️ Bulut İzleri", "📱 Mobil Kanıtlar", "📱 Mobil Adli Analiz"]
    )

    with tab_cloud:
        st.caption("AWS CloudTrail / Azure Activity Logs — `data/results/cloud_findings.json`")
        fig_hm = build_cloud_activity_heatmap_figure(cloud_payload)
        if fig_hm:
            st.plotly_chart(fig_hm, use_container_width=True)
        else:
            st.caption(
                "Isı haritası için yeterli bulut olayı yok — `cloud_findings.json` üretmek için `cloud_wrapper` çalıştırın."
            )
        fig_ph = build_cloud_provider_hour_heatmap_figure(cloud_payload)
        if fig_ph:
            st.markdown("##### İkinci ısı haritası — sağlayıcı × saat (UTC)")
            st.caption("Kritik / BULUT SIZINTISI / hibrit olaylarının gün içi dağılımı (`event_time` içinden saat, UTC).")
            st.plotly_chart(fig_ph, use_container_width=True)
        cs = cloud_payload.get("stats") or {}
        c1, c2, c3 = st.columns(3)
        c1.metric("Kritik olay", str(cs.get("critical_events", len(cloud_payload.get("critical_events") or []))))
        c2.metric("BULUT SIZINTISI", str(cs.get("bulut_sizintisi_events", len(cloud_payload.get("bulut_sizintisi") or []))))
        c3.metric("Hibrit (genel)", str(cs.get("hybrid_attack_events", len(cloud_payload.get("hybrid_attacks") or []))))
        cdf = _cloud_events_table_rows(cloud_payload)
        if len(cdf) > 0:
            st.dataframe(cdf, use_container_width=True, hide_index=True)
        else:
            st.info("`modules.cloud_wrapper` ile analiz: `CloudForensicsModule().execute( evidence, Path('data/results') )`")
        bsz = cloud_payload.get("bulut_sizintisi") or []
        if bsz:
            with st.expander("BULUT SIZINTISI (bulut IP = şüpheli ağ listesi)", expanded=True):
                st.dataframe(pd.DataFrame(bsz[:50]), use_container_width=True, hide_index=True)
        hy = cloud_payload.get("hybrid_attacks") or []
        if hy:
            with st.expander("Hibrit eşleşme (bulut IP = genel ağ çıktısı)", expanded=False):
                st.dataframe(pd.DataFrame(hy[:50]), use_container_width=True, hide_index=True)
        errs = cloud_payload.get("errors") or []
        if errs:
            st.warning("Bulut içe aktarma uyarıları: " + "; ".join(str(e) for e in errs[:5]))

    with tab_cloud_traces:
        st.markdown("##### ☁️ Bulut İzleri — kimlik, coğrafya ve başarısız denemeler")
        st.caption(
            "`cloud_findings.json` içindeki kritik + BULUT SIZINTISI + hibrit olaylar — karmaşık günlükleri özetler."
        )
        failures_only = st.checkbox(
            "Yalnızca hata alan işlemler (Access Denied / Unauthorized / Forbidden vb.)",
            value=False,
            help="Saldırganın yetki denemelerini ve red edilen API çağrılarını süzmek için açın.",
        )
        traces_df = build_cloud_traces_dataframe(cloud_payload, failures_only)
        n_all = len(_iter_all_cloud_trace_events(cloud_payload))
        c1, c2, c3 = st.columns(3)
        c1.metric("Paneldeki olay", str(len(traces_df)))
        c2.metric("Toplam iz (filtre öncesi)", str(n_all))
        c3.metric("Süzgeç", "Hatalı" if failures_only else "Tümü")

        if len(traces_df) == 0:
            st.info(
                "Gösterilecek bulut izi yok — `cloud_wrapper` ile `cloud_findings.json` üretin veya "
                "hata süzgecini kapatın."
            )
        else:
            fig_cu = build_cloud_users_bar_figure(traces_df)
            if fig_cu:
                st.plotly_chart(fig_cu, use_container_width=True)
            else:
                st.caption("Bar grafik için yeterli kimlik çeşitliliği yok.")

            fig_geo, geo_notes = build_cloud_country_map_figure(traces_df, mask_sensitive)
            for gn in geo_notes:
                st.caption(gn)
            if fig_geo:
                st.plotly_chart(fig_geo, use_container_width=True)
            else:
                st.caption("Harita: geçerli dış kaynak IP veya konum servisi gerekir.")

            with st.expander("Ham tablo — süzülmüş olaylar", expanded=False):
                show_cols = [c for c in ("timestamp", "provider", "cloud_user", "action", "status", "source_ip") if c in traces_df.columns]
                st.dataframe(
                    traces_df[show_cols] if show_cols else traces_df,
                    use_container_width=True,
                    hide_index=True,
                )

    with tab_mobile:
        st.caption(
            "FileSystem parser (rehber, WhatsApp, History) + EXIF/harita GPS — `data/results/mobile_findings.json`"
        )
        ms = mobile_payload.get("stats") or {}
        m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
        m1.metric("Rehber", str(ms.get("contacts_rows", len(mobile_payload.get("contacts") or []))))
        m2.metric("Tarayıcı", str(ms.get("browser_history_rows", len(mobile_payload.get("browser_history") or []))))
        m3.metric("WhatsApp", str(ms.get("whatsapp_rows", len(mobile_payload.get("whatsapp_messages") or []))))
        m4.metric("SMS", str(ms.get("sms_rows", len(mobile_payload.get("sms_messages") or []))))
        m5.metric("Arama", str(ms.get("call_log_rows", len(mobile_payload.get("call_logs") or []))))
        m6.metric("Konum", str(ms.get("location_rows", len(mobile_payload.get("locations") or []))))
        m7.metric("Carving", str(ms.get("carving_rows", len(mobile_payload.get("carving_findings") or []))))

        wdf_full = pd.DataFrame((mobile_payload.get("whatsapp_messages") or [])[:12000])
        fig_sankey = build_whatsapp_traffic_sankey(mobile_payload, max_jids=28)
        if fig_sankey:
            st.markdown("##### Ağ grafiği — WhatsApp mesaj trafiği (Sankey)")
            st.caption("Giden / gelen mesaj hacmi: cihaz merkez düğümü ↔ sohbet kimlikleri (JID).")
            st.plotly_chart(fig_sankey, use_container_width=True)
        elif len(wdf_full) > 0:
            st.caption("Sankey grafiği için en az iki farklı sohbet / yeterli mesaj gerekir.")
        else:
            st.caption("WhatsApp mesaj verisi yok — `msgstore.db` içeren yedek analiz edin.")

        fig_nx = build_whatsapp_networkx_graph_figure(mobile_payload)
        if fig_nx:
            st.markdown("##### Tam graf — WhatsApp (NetworkX · spring layout)")
            st.caption(
                "Mesajlar zamana göre sıralanır; ardışık **farklı** JID çiftleri kenar oluşturur (ağırlık = geçiş sayısı). "
                "Yoğun düğümler gösterim için sınırlandırılabilir."
            )
            st.plotly_chart(fig_nx, use_container_width=True)
        elif len(wdf_full) >= 3:
            try:
                import networkx as _nx_check  # noqa: F401
            except ImportError:
                st.caption("Tam NetworkX grafiği için paket gerekli: `pip install networkx`")

        ldf_map = pd.DataFrame(mobile_payload.get("locations") or [])
        deck_mob = make_mobile_evidence_location_deck(ldf_map)
        if deck_mob:
            st.markdown("##### Harita — mobil konum kanıtları")
            st.caption("SQLite konum tabloları · harita önbelleği · EXIF (yeşil noktalar).")
            st.pydeck_chart(deck_mob, use_container_width=True, height=400)
        elif len(ldf_map) > 0:
            st.caption("Konum satırları var ancak geçerli enlem/boylam parse edilemedi.")

        cdf_ct = pd.DataFrame((mobile_payload.get("contacts") or [])[:500])
        if len(cdf_ct) > 0:
            st.markdown("**Rehber (contacts2 / AddressBook)**")
            st.dataframe(cdf_ct, use_container_width=True, hide_index=True)
        bdf = pd.DataFrame((mobile_payload.get("browser_history") or [])[:400])
        if len(bdf) > 0:
            st.markdown("**Tarayıcı geçmişi (Chrome History / Safari)**")
            show_b = [c for c in ("timestamp_iso", "browser_family", "title", "url") if c in bdf.columns]
            st.dataframe(bdf[show_b] if show_b else bdf, use_container_width=True, hide_index=True)
        wdf = wdf_full.head(400).copy() if len(wdf_full) > 0 else pd.DataFrame()
        if len(wdf) > 0:
            st.markdown("**WhatsApp (özet)**")
            show_w = [c for c in ["timestamp_iso", "jid", "body", "from_me"] if c in wdf.columns]
            st.dataframe(wdf[show_w] if show_w else wdf, use_container_width=True, hide_index=True)
        cdf_calls = pd.DataFrame((mobile_payload.get("call_logs") or [])[:300])
        if len(cdf_calls) > 0:
            st.markdown("**Arama kayıtları**")
            st.dataframe(cdf_calls, use_container_width=True, hide_index=True)
        ldf = pd.DataFrame(mobile_payload.get("locations") or [])
        if len(ldf) > 0:
            st.markdown("**Konum (GPS)**")
            st.dataframe(ldf, use_container_width=True, hide_index=True)
        crdf = _mobile_carving_highlights(mobile_payload)
        if len(crdf) > 0:
            st.markdown("**Silinmiş mesaj adayları (SQLite carving)**")
            st.dataframe(crdf, use_container_width=True, hide_index=True)
        sms_preview = mobile_payload.get("sms_messages") or []
        has_any_mobile = (
            len(cdf_ct) > 0
            or len(bdf) > 0
            or len(wdf) > 0
            or len(sms_preview) > 0
            or len(cdf_calls) > 0
            or len(ldf) > 0
            or len(crdf) > 0
            or bool(ms)
        )
        if not has_any_mobile:
            st.info("`modules.mobile_wrapper` ile: `MobileForensicsModule().execute(Path('yedek'), Path('data/results'))`")

    with tab_mobile_lab:
        st.markdown(
            """
            <div style="background:linear-gradient(90deg,rgba(31,111,235,0.12),rgba(0,240,255,0.06));
            border-left:4px solid #388bfd;padding:0.85rem 1rem;border-radius:8px;margin-bottom:0.75rem;">
            <strong style="color:#e6edf3;">Mobil Kanıt Odası — Adli görünüm</strong><br/>
            <span style="color:#8b949e;font-size:0.9rem;">
            Arayüz düzeni <strong>Cellebrite UFED Cloud Analyzer</strong> tarzı sade paneller;
            kanıt yoğunluğu ve kanal ayrımı <strong>Oxygen Forensics</strong> ayrıntı seviyesini hedefler.
            </span></div>
            """,
            unsafe_allow_html=True,
        )
        st.caption(
            "Kaynak: `data/results/mobile_findings.json` — WhatsApp baloncukları `msgstore` / ChatStorage; SMS `mmssms.db`; "
            "rota son 24 saat GPS zaman damgası ile süzülür (Folium + streamlit-folium)."
        )

        chat_df = build_unified_mobile_chat_dataframe(mobile_payload)
        opts = _mobile_chat_thread_options(chat_df)
        labels = [o[0] for o in opts]
        pick = st.selectbox(
            "Sohbet / zaman çizelgesi seçin",
            options=labels,
            index=0,
            help="Tek bir JID veya SMS hattına kilitlenerek karşılıklı konuşma görünümü; 'Tüm mesajlar' kronolojik birleşik akış.",
        )
        ix = labels.index(pick)
        ch_sel, peer_sel = opts[ix][1], opts[ix][2]

        st.markdown("##### 💬 Chat Timeline — WhatsApp & SMS (baloncuk)")
        render_mobile_chat_bubble_timeline(chat_df, ch_sel, peer_sel)

        st.markdown("##### 🗺️ Rota haritası — son 24 saat (GPS)")
        route_hours = 24
        route_df, route_note = build_mobile_route_last_hours_df(mobile_payload, hours=route_hours)
        if route_note:
            st.caption(route_note)
        render_mobile_route_folium(route_df, route_hours)

    st.markdown("---")

    # --- Canlı kritiklik filtresi + zaman çizelgesi ---
    st.markdown("## 📈 Saldırı Zaman Çizelgesi")
    st.caption("Hayabusa + Chainsaw + Volatility + Zeek — Kritiklik seviyesine göre canlı süzme")

    all_levels = ["critical", "high", "medium", "low", "info"]
    level_labels = {
        "critical": "🔴 Kritik",
        "high": "🟠 Yüksek",
        "medium": "🟡 Orta",
        "low": "🟢 Düşük",
        "info": "ℹ️ Bilgi",
    }

    if not events:
        st.info(
            "Henüz disk/ağ timeline yok. `python main.py -i <evtx> -m <memory> -p <pcap>` ile doldurabilirsiniz. "
            "Bulut ve mobil panelleri yine de yukarıda çalışır."
        )
        df = pd.DataFrame(columns=["Timestamp", "Level", "Source", "RuleTitle", "Details"])
        df_f = pd.DataFrame(columns=["Timestamp", "Level", "Source", "RuleTitle", "Details", "Severity"])
    else:
        df = pd.DataFrame(events)
        df["Severity"] = df["Level"].map(_normalize_severity)

        filt = st.multiselect(
            "Kritiklik seviyesi (canlı filtre)",
            options=all_levels,
            default=all_levels,
            format_func=lambda x: level_labels.get(x, x),
            help="Seçili seviyelere göre tablo ve grafik anında güncellenir.",
        )
        if not filt:
            st.warning("En az bir kritiklik seviyesi seçin.")
            filt = all_levels

        df_f = df[df["Severity"].isin(filt)].copy()
        df_f["Timestamp"] = pd.to_datetime(df_f["Timestamp"], errors="coerce")
        df_f = df_f.dropna(subset=["Timestamp"])
        df_f = df_f.sort_values("Timestamp")

        st.caption(f"Gösterilen olay: **{len(df_f)}** / {len(df)}")

    if len(df_f) > 0:
        fig = px.scatter(
            df_f,
            x="Timestamp",
            y="Source",
            color="Level",
            hover_data=["RuleTitle", "Details", "Severity"],
            color_discrete_map={
                "critical": "#f85149",
                "crit": "#f85149",
                "high": "#da3633",
                "yüksek": "#da3633",
                "medium": "#d29922",
                "orta": "#d29922",
                "low": "#9e6a03",
                "düşük": "#9e6a03",
                "info": "#388bfd",
            },
            title="Birleşik Olay Zaman Çizelgesi (filtrelenmiş)",
        )
        fig.update_layout(
            height=450,
            template="plotly_dark",
            paper_bgcolor="rgba(10,22,40,0.95)",
            plot_bgcolor="rgba(13,27,42,0.95)",
            font=dict(color="#e6edf3", family="Segoe UI"),
        )
        st.plotly_chart(fig, use_container_width=True)
        render_analyst_notebook(df_f, mask_sensitive)
    else:
        st.warning("Bu kritiklik filtresiyle eşleşen olay yok; filtreleri genişletin.")

    # --- Dosya ağacı (KAPE / Volatility / ayıklanan dosyalar) ---
    st.markdown("### 🌲 Şüpheli Dosya Ağacı")
    st.caption("KAPE çıktı dizini, Volatility süreç yolları ve ağdan ayıklanan dosyalar — ağaç görünümü")
    file_paths = collect_suspicious_file_paths()
    if file_paths:
        tree = _path_to_nested_tree(file_paths)
        html = (
            '<div style="background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;'
            'padding:12px;max-height:420px;overflow-y:auto">'
            + _render_tree_html(tree)
            + "</div>"
        )
        components.html(html, height=440, scrolling=True)
    else:
        st.info("Şüpheli dosya yolu bulunamadı. Volatility (malfind/pslist), KAPE çıktısı veya PCAP dosya ayıklama ekleyin.")

    tab_overview, tab_disk, tab_memory, tab_network = st.tabs(["📊 Genel", "💾 Disk", "🧠 Bellek", "🌐 Ağ"])

    with tab_overview:
        show_cols = ["Timestamp", "Level", "Source", "RuleTitle", "Details"]
        st.dataframe(
            df_f[show_cols] if len(df_f) > 0 else pd.DataFrame(columns=show_cols),
            use_container_width=True,
            hide_index=True,
            column_config={"Timestamp": st.column_config.DatetimeColumn("Zaman", format="YYYY-MM-DD HH:mm:ss")},
        )

    with tab_disk:
        hayabusa = _load_json(RESULTS / "hayabusa_output.json") or _load_json(RESULTS / "hayabusa.json")
        chainsaw = _load_json(RESULTS / "chainsaw_output.json")
        disk_events = [e for e in events if e.get("Source") in ("Hayabusa", "Chainsaw")]
        if disk_events:
            st.dataframe(pd.DataFrame(disk_events), use_container_width=True, hide_index=True)
        else:
            st.info("Disk verisi yok. Hayabusa/Chainsaw çıktıları bekleniyor.")

    with tab_memory:
        vol_pslist = _load_json(RESULTS / "volatility" / "windows_pslist.json")
        vol_netscan = _load_json(RESULTS / "volatility" / "windows_netscan.json")
        vol_malfind = _load_json(RESULTS / "volatility" / "windows_malfind.json")
        mem_events = [e for e in events if e.get("Source") == "Volatility"]
        if mem_events:
            st.dataframe(pd.DataFrame(mem_events), use_container_width=True, hide_index=True)
        if vol_pslist or vol_netscan or vol_malfind:
            with st.expander("Ham Volatility çıktısı"):
                st.json(
                    {
                        "pslist": vol_pslist[:5] if isinstance(vol_pslist, list) else vol_pslist,
                        "malfind_count": len(vol_malfind) if isinstance(vol_malfind, list) else 0,
                    }
                )
        else:
            st.info("Bellek verisi yok. Volatility çıktıları bekleniyor.")

    with tab_network:
        net = _load_json(RESULTS / "network_analysis.json") or _load_json(RESULTS / "network" / "analysis_summary.json")
        net_events = [e for e in events if e.get("Source") == "Zeek"]
        if net_events:
            st.dataframe(pd.DataFrame(net_events), use_container_width=True, hide_index=True)
        if isinstance(net, dict):
            with st.expander("DNS Tünelleme / Beaconing"):
                st.write("DNS Tünelleme Şüphesi:", len(net.get("dns_tunneling_suspicious", [])))
                st.write("Beaconing (Alışılmadık Port):", len(net.get("beaconing_suspicious", [])))
        else:
            st.info("Ağ verisi yok. Zeek/Tshark çıktıları bekleniyor.")

    st.markdown("---")
    st.markdown("## 📥 Analiz Raporunu PDF/HTML Olarak İndir")
    try:
        from core.reporter import DEFAULT_CASE_TITLE, generate_html_report, generate_pdf_report

        cross_align = None
        try:
            ap = RESULTS / "cross_source_alignment.json"
            if ap.exists():
                cross_align = json.loads(ap.read_text(encoding="utf-8", errors="ignore"))
                if not isinstance(cross_align, dict):
                    cross_align = None
        except (json.JSONDecodeError, OSError):
            cross_align = None

        html_path = RESULTS / "diz_rapor.html"
        pdf_path = RESULTS / "diz_rapor.pdf"
        generate_html_report(
            events,
            html_path,
            title=DEFAULT_CASE_TITLE,
            mask_sensitive=mask_sensitive,
            confirmed_threats=confirmed_threats,
            exfiltration_threats=exfil_threats,
            account_takeover_threats=ato_threats,
            full_spectrum_threats=fs_threats,
            cross_alignment=cross_align,
        )
        html_content = html_path.read_text(encoding="utf-8")

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "📄 HTML Raporu İndir",
                html_content,
                file_name="diz_analiz_raporu.html",
                mime="text/html",
                use_container_width=True,
            )
        with col2:
            pdf_out = generate_pdf_report(
                events,
                pdf_path,
                html_path=html_path,
                title=DEFAULT_CASE_TITLE,
                mask_sensitive=mask_sensitive,
                confirmed_threats=confirmed_threats,
                exfiltration_threats=exfil_threats,
                account_takeover_threats=ato_threats,
                full_spectrum_threats=fs_threats,
                cross_alignment=cross_align,
            )
            if pdf_out and pdf_out.exists():
                pdf_bytes = pdf_out.read_bytes()
                st.download_button(
                    "📕 PDF Raporu İndir",
                    pdf_bytes,
                    file_name="diz_analiz_raporu.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            else:
                st.info("PDF için: pip install weasyprint")
    except Exception as e:
        st.error(f"Rapor oluşturulamadı: {e}")


if __name__ == "__main__":
    main()
