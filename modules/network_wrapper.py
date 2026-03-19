"""
Dijital İz Sürücü - Ağ Analizi Modülü
PCAP dosyalarından HTTP, DNS, bağlantı ve dosya ayıklama.

Zeek (Bro) veya Tshark (Wireshark CLI) kullanır.
Arkime ve NetworkMiner'ın 'Dosya Ayıklama' (File Extraction) mantığını
simüle ederek şüpheli EXE/scriptleri raporlar.

Atıf: Arkime, NetworkMiner - Ağ forensik standartları.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Şüpheli dosya türleri (Arkime/NetworkMiner tarzı)
SUSPICIOUS_MIME_TYPES = (
    "application/x-dosexec",      # EXE
    "application/x-msdownload",
    "application/octet-stream",   # Genellikle binary
    "application/x-executable",
    "text/x-msdos-batch",         # BAT
    "application/x-msi",          # MSI
    "application/vnd.ms-cab",      # CAB
)

SUSPICIOUS_EXTENSIONS = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr")

# Standart portlar (dışı = Beaconing şüphesi)
STANDARD_PORTS = {80, 443, 53, 22, 25, 110, 143, 993, 995, 21, 20, 445, 139, 3389, 5900, 8080, 8443, 3128}

# DNS tünelleme: uzun subdomain, base64 benzeri
DNS_TUNNEL_MIN_LEN = 40


def _resolve_zeek() -> str | None:
    """Zeek veya Bro binary'sini bulur."""
    for cmd in ("zeek", "bro"):
        if shutil.which(cmd):
            return cmd
    for exe in (_ROOT / "zeek", _ROOT / "bro"):
        if exe.exists():
            return str(exe)
    return None


def _resolve_tshark() -> str | None:
    """Tshark binary'sini bulur."""
    if shutil.which("tshark"):
        return "tshark"
    for exe in (_ROOT / "tshark.exe", _ROOT / "tshark"):
        if exe.exists():
            return str(exe)
    return None


def _find_pcap(path: str | Path) -> list[Path]:
    """PCAP/PCAPNG dosyalarını toplar."""
    p = Path(path)
    if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        return [p]
    if p.is_dir():
        return list(p.rglob("*.pcap")) + list(p.rglob("*.pcapng")) + list(p.rglob("*.cap"))
    return []


def _parse_zeek_json_log(log_path: Path) -> list[dict]:
    """Zeek JSON log dosyasını satır satır parse eder."""
    if not log_path.exists():
        return []
    out = []
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _run_zeek(pcap_path: Path, work_dir: Path, timeout: int = 600) -> bool:
    """Zeek ile PCAP analizi. JSON log üretir."""
    zeek = _resolve_zeek()
    if not zeek:
        return False
    cmd = [
        zeek,
        "-r", str(pcap_path),
        "LogAscii::use_json=T",
    ]
    try:
        subprocess.run(
            cmd,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def _run_tshark_json(pcap_path: Path, display_filter: str, timeout: int = 300) -> list[dict]:
    """Tshark ile JSON çıktı alır."""
    tshark = _resolve_tshark()
    if not tshark:
        return []
    if display_filter:
        cmd = [tshark, "-r", str(pcap_path), "-T", "json", "-Y", display_filter]
    else:
        cmd = [tshark, "-r", str(pcap_path), "-T", "json"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout or "[]")
        return data if isinstance(data, list) else [data]
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []


def _tshark_http_to_records(raw: list[dict]) -> list[dict]:
    """Tshark JSON çıktısından HTTP kayıtları çıkarır."""
    out = []
    for pkt in raw:
        if not isinstance(pkt, dict):
            continue
        src = pkt.get("_source", pkt)
        layers = src.get("layers", src)
        if not isinstance(layers, dict):
            continue
        frame = layers.get("frame", {}) or {}
        ip_src = layers.get("ip", {})
        if isinstance(ip_src, dict):
            host = ip_src.get("ip.src") or ip_src.get("ip.dst") or ""
        else:
            host = str(ip_src)[:50]
        http = layers.get("http", {}) or layers.get("http.request", {}) or {}
        req = http.get("http.request.uri") or http.get("http.request.uri.query") or ""
        method = http.get("http.request.method") or "GET"
        ts = frame.get("frame.time") if isinstance(frame, dict) else ""
        out.append({
            "ts": str(ts)[:50],
            "host": str(host)[:50],
            "uri": str(req)[:500],
            "method": str(method)[:20],
        })
    return out


def _tshark_dns_to_records(raw: list[dict]) -> list[dict]:
    """Tshark JSON çıktısından DNS kayıtları çıkarır."""
    out = []
    for pkt in raw:
        if not isinstance(pkt, dict):
            continue
        src = pkt.get("_source", pkt)
        layers = src.get("layers", src)
        if not isinstance(layers, dict):
            continue
        frame = layers.get("frame", {}) or {}
        ts = frame.get("frame.time") if isinstance(frame, dict) else ""
        dns = layers.get("dns", {}) or {}
        qry = dns.get("dns.qry.name") if isinstance(dns, dict) else ""
        if not qry and isinstance(dns, dict):
            for k, v in dns.items():
                if "qry" in k.lower() and "name" in k.lower():
                    qry = v
                    break
        out.append({
            "ts": str(ts)[:50],
            "query": str(qry)[:253] if qry else "",
        })
    return out


def _is_dns_tunneling_suspicious(query: str) -> bool:
    """DNS tünelleme şüphesi: uzun subdomain, base64 benzeri karakterler."""
    if not query or len(query) < DNS_TUNNEL_MIN_LEN:
        return False
    # Uzun tek label (subdomain.data.com -> subdomain çok uzunsa)
    labels = query.lower().split(".")
    for lbl in labels:
        if len(lbl) >= DNS_TUNNEL_MIN_LEN:
            b64_ratio = sum(1 for c in lbl if c in "abcdefghijklmnopqrstuvwxyz0123456789+/=-_") / max(len(lbl), 1)
            if b64_ratio > 0.85:
                return True
    return False


def _is_unusual_port(port: int) -> bool:
    """Alışılmadık port = Beaconing şüphesi."""
    return port not in STANDARD_PORTS and 1 <= port <= 65535


def _apply_masking(data: Any, mask_ips: bool) -> Any:
    """core/masking ile IP maskeleme."""
    if not mask_ips:
        return data
    try:
        from core.masking import mask_data
    except ImportError:
        return data
    if isinstance(data, str):
        return mask_data(data, mask_ips=True)
    if isinstance(data, dict):
        return {k: _apply_masking(v, mask_ips) for k, v in data.items()}
    if isinstance(data, list):
        return [_apply_masking(x, mask_ips) for x in data]
    return data


def _is_suspicious_file(entry: dict) -> bool:
    """files.log kaydı şüpheli EXE/script mi?"""
    mime = (entry.get("mime_type") or entry.get("mime-type") or "").lower()
    fname = (entry.get("filename") or entry.get("tx_hosts") or "").lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in fname or fname.endswith(ext):
            return True
    return mime in SUSPICIOUS_MIME_TYPES


def _run_tshark_export_objects(pcap_path: Path, protocol: str, out_dir: Path, timeout: int = 300) -> list[Path]:
    """Tshark --export-objects ile dosya ayıklama (Arkime/NetworkMiner tarzı)."""
    tshark = _resolve_tshark()
    if not tshark:
        return []
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [tshark, "-r", str(pcap_path), "--export-objects", f"{protocol},{out_dir}"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return list(out_dir.glob("*"))
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []


class NetworkWrapper:
    """
    PCAP analiz modülü - Zeek veya Tshark ile.

    Kullanım:
        nw = NetworkWrapper()
        results = nw.run_analysis("capture.pcap")
    """

    def __init__(
        self,
        zeek_path: str | None = None,
        tshark_path: str | None = None,
        output_base: str | Path | None = None,
    ):
        self.zeek_path = zeek_path or _resolve_zeek()
        self.tshark_path = tshark_path or _resolve_tshark()
        self.output_base = Path(output_base) if output_base else _ROOT / "data" / "results" / "network"

    def run_analysis(
        self,
        pcap_path: str | Path,
        extract_files: bool = True,
        mask_ips: bool = False,
        timeout: int = 600,
    ) -> dict[str, Any]:
        """
        PCAP dosyasını analiz eder. HTTP, DNS tünelleme şüphesi, Beaconing (alışılmadık port).

        Args:
            pcap_path: PCAP dosyası veya klasör
            extract_files: Tshark ile HTTP/SMB dosya ayıklama (NetworkMiner tarzı)
            mask_ips: core/masking.py ile IP adreslerini maskele (KVKK)
            timeout: Analiz timeout (saniye)

        Returns:
            {
                "success": bool,
                "output_dir": str,
                "http_requests": [...],
                "dns_queries": [...],
                "connections": [...],
                "suspicious_files": [...],
                "extracted_files": [...]
            }
        """
        pcaps = _find_pcap(pcap_path)
        if not pcaps:
            return {
                "success": False,
                "output_dir": str(self.output_base),
                "http_requests": [],
                "dns_queries": [],
                "connections": [],
                "suspicious_files": [],
                "extracted_files": [],
                "errors": ["PCAP dosyasi bulunamadi"],
            }

        self.output_base.mkdir(parents=True, exist_ok=True)
        work_dir = self.output_base / "zeek_work"
        work_dir.mkdir(parents=True, exist_ok=True)

        http_requests: list[dict] = []
        dns_queries: list[dict] = []
        connections: list[dict] = []
        suspicious_files: list[dict] = []
        extracted_paths: list[str] = []
        errors: list[str] = []

        # 1. Zeek ile analiz (tercih)
        if self.zeek_path:
            pcap = pcaps[0]
            if _run_zeek(pcap, work_dir, timeout):
                conn_log = work_dir / "conn.log"
                http_log = work_dir / "http.log"
                dns_log = work_dir / "dns.log"
                files_log = work_dir / "files.log"

                for p in conn_log, http_log, dns_log, files_log:
                    if p.exists():
                        rows = _parse_zeek_json_log(p)
                        if "conn" in p.name:
                            connections.extend(rows)
                        elif "http" in p.name:
                            http_requests.extend(rows)
                        elif "dns" in p.name:
                            dns_queries.extend(rows)
                        elif "files" in p.name:
                            for r in rows:
                                if _is_suspicious_file(r):
                                    suspicious_files.append(r)

        # 2. Zeek yoksa Tshark fallback
        if not http_requests and self.tshark_path:
            raw_http = _run_tshark_json(pcaps[0], "http.request", timeout)
            http_requests = _tshark_http_to_records(raw_http)
        if not dns_queries and self.tshark_path:
            raw_dns = _run_tshark_json(pcaps[0], "dns", timeout)
            dns_queries = _tshark_dns_to_records(raw_dns)
        if not connections and self.tshark_path:
            raw_conn = _run_tshark_json(pcaps[0], "tcp or udp", timeout)
            for p in raw_conn[:500]:
                connections.append(p)

        # 2b. DNS tünelleme şüphesi işaretle
        dns_tunneling_suspicious: list[dict] = []
        for d in dns_queries:
            q = d.get("query") or d.get("dns.qry.name") or ""
            if _is_dns_tunneling_suspicious(str(q)):
                rec = dict(d)
                rec["dns_tunneling_suspicious"] = True
                dns_tunneling_suspicious.append(rec)

        # 2c. Alışılmadık port (Beaconing) işaretle
        beaconing_connections: list[dict] = []
        for c in connections:
            if not isinstance(c, dict):
                continue
            port = (
                c.get("id.resp_p") or c.get("id.orig_p") or
                c.get("resp_p") or c.get("orig_p") or
                c.get("tcp.dstport") or c.get("udp.dstport")
            )
            try:
                p = int(port) if port is not None else 0
            except (ValueError, TypeError):
                p = 0
            if p and _is_unusual_port(p):
                rec = dict(c)
                rec["beaconing_suspicious"] = True
                rec["unusual_port"] = p
                beaconing_connections.append(rec)

        # 3. IP maskeleme (KVKK)
        if mask_ips:
            http_requests = _apply_masking(http_requests, True)
            dns_queries = _apply_masking(dns_queries, True)
            connections = _apply_masking(connections, True)
            dns_tunneling_suspicious = _apply_masking(dns_tunneling_suspicious, True)
            beaconing_connections = _apply_masking(beaconing_connections, True)

        # 4. Dosya ayıklama (Arkime/NetworkMiner simülasyonu)
        if extract_files and self.tshark_path:
            extract_dir = self.output_base / "extracted_files"
            for proto in ("http", "smb"):
                extracted = _run_tshark_export_objects(pcaps[0], proto, extract_dir / proto, timeout)
                extracted_paths.extend(str(p) for p in extracted)
            # Şüpheli uzantılı ayıklanan dosyaları raporla
            if extract_dir.exists():
                for p in extract_dir.rglob("*"):
                    if p.is_file() and any(p.name.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                        suspicious_files.append({
                            "filename": p.name,
                            "extracted_path": str(p),
                            "source": "tshark_export",
                        })

        # 5. network_analysis.json (ana çıktı - data/results/)
        out = {
            "http_traffic": http_requests[:2000],
            "dns_queries": dns_queries[:2000],
            "dns_tunneling_suspicious": dns_tunneling_suspicious,
            "connections": connections[:5000],
            "beaconing_suspicious": beaconing_connections,
            "suspicious_files": suspicious_files,
        }
        results_dir = _ROOT / "data" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        network_analysis_path = results_dir / "network_analysis.json"
        with open(network_analysis_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)

        # Geriye dönük uyumluluk: network/ altına da kaydet
        summary_path = self.output_base / "analysis_summary.json"
        self.output_base.mkdir(parents=True, exist_ok=True)
        compat_out = {
            "http_requests": http_requests[:2000],
            "dns_queries": dns_queries[:2000],
            "connections": connections[:5000],
            "suspicious_files": suspicious_files,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(compat_out, f, ensure_ascii=False, indent=2)

        return {
            "success": len(http_requests) > 0 or len(dns_queries) > 0 or len(connections) > 0,
            "output_dir": str(self.output_base),
            "network_analysis_path": str(network_analysis_path),
            "http_requests": http_requests,
            "dns_queries": dns_queries,
            "dns_tunneling_suspicious": dns_tunneling_suspicious,
            "beaconing_suspicious": beaconing_connections,
            "connections": connections,
            "suspicious_files": suspicious_files,
            "extracted_files": extracted_paths,
            "errors": errors,
        }
