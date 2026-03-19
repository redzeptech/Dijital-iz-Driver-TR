"""
Dijital İz Sürücü - Profesyonel Dashboard
Timesketch / Azure Monitor temizliği, Cellebrite UFED detaycılığı.

Sol panel: Disk, Bellek, Ağ sekmeleri
Ana ekran: Saldırı Zaman Çizelgesi + Tehdit Haritası
KVKK: Maskeli / Maskesiz görüntüleme
"""

import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "results"


def _load_json(path: Path) -> list | dict:
    """JSON dosyasını yükle."""
    if not path.exists():
        return [] if "list" in str(type(path)) else {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data] if data else []
    except (json.JSONDecodeError, Exception):
        return []


def _extract_ips_from_text(text: str) -> set[str]:
    """Metinden IPv4 adreslerini çıkarır."""
    if not text:
        return set()
    pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    return set(re.findall(pattern, str(text)))


def _ip_to_geo(ip: str) -> tuple[float, float] | None:
    """IP için lat/lon döner (ip-api.com, ücretsiz)."""
    if not ip or ip.startswith(("127.", "10.", "172.16.", "192.168.")):
        return None
    try:
        req = Request(f"http://ip-api.com/json/{ip}?fields=lat,lon,status", headers={"User-Agent": "DIZ/1.0"})
        with urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            return (float(data["lat"]), float(data["lon"]))
    except (URLError, json.JSONDecodeError, KeyError, Exception):
        pass
    return None


def _load_timeline_events() -> list[dict]:
    """Tüm kaynaklardan timeline olaylarını toplar."""
    events: list[dict] = []

    # Hayabusa
    for p in [RESULTS / "hayabusa_output.json", RESULTS / "hayabusa.json"]:
        data = _load_json(p)
        if isinstance(data, list):
            for e in data:
                if isinstance(e, dict):
                    ts = e.get("Timestamp") or e.get("timestamp") or ""
                    events.append({
                        "Timestamp": str(ts)[:19],
                        "Level": e.get("Level") or e.get("level") or "info",
                        "RuleTitle": e.get("RuleTitle") or e.get("Rule Title") or "",
                        "Details": e.get("Details") or e.get("details") or "",
                        "Source": "Hayabusa",
                    })
            break

    # Chainsaw
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

    # Volatility netscan
    net_path = RESULTS / "volatility" / "windows_netscan.json"
    if net_path.exists():
        data = _load_json(net_path)
        if isinstance(data, dict):
            rows = data.get("__children", [])
        else:
            rows = data if isinstance(data, list) else []
        for r in rows:
            if isinstance(r, dict):
                ts = r.get("CreateTime") or r.get("Timestamp") or ""
                local = r.get("LocalAddress") or r.get("LocalAddr") or ""
                remote = r.get("RemoteAddress") or r.get("RemoteAddr") or ""
                events.append({
                    "Timestamp": str(ts)[:19],
                    "Level": "info",
                    "RuleTitle": "NETWORK_MEMORY",
                    "Details": f"Local: {local} -> Remote: {remote}",
                    "Source": "Volatility",
                })

    # Network (Zeek/Tshark)
    http_path = RESULTS / "network" / "http_requests.json"
    for e in _load_json(http_path) if http_path.exists() else []:
        if isinstance(e, dict):
            events.append({
                "Timestamp": str(e.get("ts") or "")[:19],
                "Level": "info",
                "RuleTitle": "HTTP",
                "Details": f"{e.get('method','')} {e.get('uri','')} -> {e.get('host','')}",
                "Source": "Ağ",
            })

    return events


def _extract_ip_from_conn(c: dict) -> list[str]:
    """Bağlantı objesinden IP'leri çıkarır (Zeek/Tshark farklı formatlar)."""
    ips = []
    for key in ("id.orig_h", "id.resp_h", "orig_h", "resp_h"):
        v = c.get(key)
        if isinstance(v, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
            ips.append(v)
    layers = c.get("layers") or c.get("_source", {}).get("layers") or {}
    if isinstance(layers, dict):
        ip_layer = layers.get("ip", {})
        if isinstance(ip_layer, dict):
            for k in ("ip.src", "ip.dst"):
                v = ip_layer.get(k)
                if isinstance(v, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", v):
                    ips.append(v)
    return ips


def _load_ips_for_map() -> list[dict]:
    """Harita için IP listesi (lat, lon, ip)."""
    ips_seen: set[str] = set()
    out: list[dict] = []

    # Network connections
    conn_path = RESULTS / "network" / "analysis_summary.json"
    if conn_path.exists():
        data = _load_json(conn_path)
        if isinstance(data, dict):
            for c in data.get("connections", [])[:200]:
                if isinstance(c, dict):
                    for ip in _extract_ip_from_conn(c):
                        if ip not in ips_seen:
                            ips_seen.add(ip)
                            geo = _ip_to_geo(ip)
                            if geo:
                                out.append({"ip": ip, "lat": geo[0], "lon": geo[1]})

    # HTTP requests
    http_path = RESULTS / "network" / "http_requests.json"
    for e in _load_json(http_path) if http_path.exists() else []:
        if isinstance(e, dict):
            host = e.get("host") or e.get("id.resp_h") or e.get("resp_h") or ""
            if host and host not in ips_seen:
                ips_seen.add(host)
                geo = _ip_to_geo(host)
                if geo:
                    out.append({"ip": host, "lat": geo[0], "lon": geo[1]})

    # Timeline'dan IP çıkar
    for ev in _load_timeline_events():
        for ip in _extract_ips_from_text(str(ev.get("Details", "")) + str(ev.get("RuleTitle", ""))):
            if ip not in ips_seen:
                ips_seen.add(ip)
                geo = _ip_to_geo(ip)
                if geo:
                    out.append({"ip": ip, "lat": geo[0], "lon": geo[1]})

    return out


def _apply_mask(events: list[dict], mask: bool) -> list[dict]:
    """Olaylara maskeleme uygular."""
    if not mask:
        return events
    try:
        from core.masking import mask_data
        return [
            {**e, "RuleTitle": mask_data(e.get("RuleTitle", "")), "Details": mask_data(e.get("Details", ""))}
            for e in events
        ]
    except ImportError:
        return events


def _level_color(level: str) -> str:
    l = (level or "").lower()
    if l in ("critical", "crit"): return "#f85149"
    if l in ("high", "yüksek"): return "#da3633"
    if l in ("medium", "orta"): return "#d29922"
    if l in ("low", "düşük"): return "#9e6a03"
    return "#388bfd"


def main() -> None:
    st.set_page_config(
        page_title="DİZ Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # KVKK: Maskeli / Maskesiz
    st.sidebar.markdown("### 🔒 KVKK Görüntüleme")
    mask_sensitive = st.sidebar.toggle("**Maskeli** görüntüle (hassas veri gizle)", value=True)
    st.sidebar.caption("Cellebrite/AXIOM tarzı kişisel veri koruma")

    # Sol panel sekmeleri: Disk, Bellek, Ağ
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📂 Veri Kaynakları")
    tab_disk, tab_mem, tab_net = st.sidebar.tabs(["💾 Disk", "🧠 Bellek", "🌐 Ağ"])

    with tab_disk:
        hayabusa_ok = (RESULTS / "hayabusa_output.json").exists() or (RESULTS / "hayabusa.json").exists()
        chainsaw_ok = (RESULTS / "chainsaw_output.json").exists()
        st.markdown("**Hayabusa/Chainsaw**")
        st.markdown(f"Hayabusa: {'✅ Yüklü' if hayabusa_ok else '❌ Yok'}")
        st.markdown(f"Chainsaw: {'✅ Yüklü' if chainsaw_ok else '❌ Yok'}")

    with tab_mem:
        vol_dir = RESULTS / "volatility"
        vol_ok = (vol_dir / "windows_pslist.json").exists() or (vol_dir / "windows_netscan.json").exists()
        st.markdown("**Volatility**")
        st.markdown(f"Bellek analizi: {'✅ Yüklü' if vol_ok else '❌ Yok'}")

    with tab_net:
        net_dir = RESULTS / "network"
        net_ok = (net_dir / "http_requests.json").exists() or (net_dir / "analysis_summary.json").exists()
        st.markdown("**Zeek/Tshark**")
        st.markdown(f"Ağ analizi: {'✅ Yüklü' if net_ok else '❌ Yok'}")

    # Ana içerik
    st.title("🛡️ Dijital İz Sürücü - Analiz Dashboard")
    st.caption("Timesketch / Azure Monitor tarzı — Cellebrite UFED detaycılığı")

    events = _load_timeline_events()
    events = _apply_mask(events, mask_sensitive)

    if not events:
        st.info("Henüz analiz verisi yok. Önce `python main.py -i <evtx_klasörü>` ile analiz çalıştırın.")
        st.markdown("**Örnek:** `python main.py -i data/raw -m memory.raw -r rapor.html`")
        return

    # Saldırı Zaman Çizelgesi (Plotly)
    st.markdown("## 📈 Saldırı Zaman Çizelgesi")
    df = pd.DataFrame(events)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df = df.sort_values("Timestamp")

    if len(df) > 0:
        df["color"] = df["Level"].apply(_level_color)
        fig = px.scatter(
            df,
            x="Timestamp",
            y="Source",
            color="Level",
            hover_data=["RuleTitle", "Details"],
            color_discrete_map={
                "critical": "#f85149", "crit": "#f85149",
                "high": "#da3633", "yüksek": "#da3633",
                "medium": "#d29922", "orta": "#d29922",
                "low": "#9e6a03", "düşük": "#9e6a03",
                "info": "#388bfd",
            },
            title="Olay Zaman Çizelgesi",
        )
        fig.update_layout(
            height=400,
            template="plotly_dark",
            paper_bgcolor="rgba(15,20,25,0.9)",
            plot_bgcolor="rgba(26,31,38,0.9)",
            font=dict(color="#e6edf3"),
            xaxis=dict(gridcolor="rgba(48,54,61,0.5)"),
            yaxis=dict(gridcolor="rgba(48,54,61,0.5)"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Zaman damgalı olay bulunamadı.")

    # Tehdit Haritası
    st.markdown("## 🗺️ Tehdit Haritası")
    ip_data = _load_ips_for_map()
    if ip_data:
        map_df = pd.DataFrame(ip_data)
        fig_map = px.scatter_geo(
            map_df,
            lat="lat",
            lon="lon",
            hover_name="ip",
            size=[10] * len(map_df),
            title="Şüpheli IP Konumları",
        )
        fig_map.update_geos(
            projection_type="natural earth",
            showland=True,
            landcolor="rgb(30,40,50)",
            oceancolor="rgb(15,25,35)",
        )
        fig_map.update_layout(
            height=400,
            template="plotly_dark",
            paper_bgcolor="rgba(15,20,25,0.9)",
            font=dict(color="#e6edf3"),
        )
        st.plotly_chart(fig_map, use_container_width=True)
        with st.expander("IP Listesi"):
            st.dataframe(map_df[["ip", "lat", "lon"]], use_container_width=True, hide_index=True)
    else:
        st.info("Haritada gösterilecek şüpheli IP bulunamadı. Ağ analizi veya timeline'da IP olmalı.")

    # Detay tablosu (Cellebrite UFED detaycılığı)
    st.markdown("## 📋 Olay Detayları")
    level_opts = df["Level"].unique().tolist() if len(df) > 0 else []
    source_opts = df["Source"].unique().tolist() if len(df) > 0 else []
    level_filter = st.multiselect("Seviye filtresi", options=level_opts, default=level_opts)
    source_filter = st.multiselect("Kaynak filtresi", options=source_opts, default=source_opts)
    filtered = df.copy()
    if level_filter:
        filtered = filtered[filtered["Level"].isin(level_filter)]
    if source_filter:
        filtered = filtered[filtered["Source"].isin(source_filter)]
    st.dataframe(
        filtered[["Timestamp", "Level", "Source", "RuleTitle", "Details"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Timestamp": st.column_config.DatetimeColumn("Zaman", format="YYYY-MM-DD HH:mm:ss"),
            "Details": st.column_config.TextColumn("Detay", width="large"),
        },
    )


if __name__ == "__main__":
    main()
