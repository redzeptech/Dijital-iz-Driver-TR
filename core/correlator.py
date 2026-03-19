"""
Dijital İz Sürücü - Disk + Bellek + Ağ Korelasyonu
Üçlü Korelasyon (Triple Cross-Check): Ağ + Bellek + Disk doğrulaması.

Akıllı Bulut-Yerel: Zeek HTTP (AWS/Azure API yoğunluğu) + cloud_findings (yetki değişimi)
+ Chainsaw (PowerShell Cloud Module) → BULUT HESABI ELE GEÇİRME (Account Takeover), öncelik 1.

**DİZ-Tam-Saha-Pres:** Mobil (şüpheli APK/IPA) + Zeek (yerel ağ sunucusuna sızdırma) + Bulut (aynı IP ile
admin/yetki denemesi) + Disk (Hayabusa lateral movement) → **TOPYEKÜN SİBER SALDIRI** birleşik raporu.

Cellebrite ve Magnet AXIOM'un gelişmiş vaka bağlama yeteneğine atıfta bulunur.
Türkiye Siber Güvenlik Standartlarına uygun teknik özet üretir.

**MITRE ATT&CK eşlemesi:** İmza tabanlı teknik/taktik etiketleri ve matris ilerleme özeti;
Velociraptor VQL ile yapılan taktik sorgu derinliğini rapor yüzeyine taşır.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
RESULTS = _ROOT / "data" / "results"

# Yoğun veri akışı eşiği (byte) - exfiltrasyon şüphesi
EXFIL_BYTE_THRESHOLD = 50_000  # 50 KB

# --- Bulut API oturumu + yerel PowerShell bulut modülü (Account Takeover korelasyonu) ---
# Zeek HTTP URI/host veya Tshark çıktısında bu parçalar AWS/Azure yönetim veya API uçlarına işaret eder.
CLOUD_API_HOST_KEYWORDS: tuple[str, ...] = (
    "amazonaws.com",
    "amazon.com",
    "aws.amazon.com",
    "execute-api.",
    "cloudfront.net",
    "management.azure.com",
    "management.core.windows.net",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "azure.com",
    "blob.core.windows.net",
    "sts.amazonaws.com",
    "signin.aws.amazon.com",
    "ingestion.monitor.azure.com",
)

# Aynı anda çok istek = "yoğun" (şüpheli / beaconing IP ile birlikte daha düşük eşik)
CLOUD_API_REQUESTS_HEAVY: int = 12
CLOUD_API_REQUESTS_WITH_BEACON: int = 4
# CloudTrail / Activity zamanı ile HTTP zamanı arasındaki pencere (saniye)
CLOUD_NET_TIME_WINDOW_SEC: int = 120
# Yerel disk (Chainsaw) olayı ile bulut olayı arası pencere (aynı oturum varsayımı)
DISK_CLOUD_TIME_WINDOW_SEC: int = 900

# Chainsaw/Hayabusa: PowerShell bulut cmdlet / modül ayak izleri
PS_CLOUD_MODULE_KEYWORDS: tuple[str, ...] = (
    "awspowershell",
    "aws.tools",
    "import-module aws",
    "install-module aws",
    "connect-azaccount",
    "az.accounts",
    "azurerm",
    "azuread",
    "microsoft.azure.commands",
    "save-azcontext",
    "get-azresource",
    "invoke-azrestmethod",
    "connect-mggraph",
    "powershell cloud",
    "awsshell",
)

# AWS/Azure yetki / kimlik yüzeyi değişimi (kısmi eşleşme, lower)
CLOUD_PRIVILEGE_ACTION_KEYWORDS: tuple[str, ...] = (
    "createuser",
    "deleteuser",
    "attachuserpolicy",
    "attachrolepolicy",
    "putuserpolicy",
    "putrolepolicy",
    "detachuserpolicy",
    "detachrolepolicy",
    "createaccesskey",
    "deleteaccesskey",
    "createloginprofile",
    "updateloginprofile",
    "putbucketpolicy",
    "deletebucketpolicy",
    "putrolepolicy",
    "assumerole",
    "setdefaultpolicyversion",
    "createinstanceprofile",
    "addroletoinstanceprofile",
    "passrole",
    "createpolicyversion",
    "attachgrouppolicy",
    "creategroup",
    "roleassignments/write",
    "roledefinitions/write",
    "roleassignments/delete",
    "elevateaccess",
    "authorization/elevateaccess",
    "networksecuritygroups/securityrules/write",
    "securityrules/write",
    "virtualmachines/delete",
)

# --- DİZ Tam-Saha-Pres (Full-Spectrum): Mobil + LAN sızdırma + Bulut admin + Disk lateral ---
INTERNAL_LAN_EXFIL_BYTE_THRESHOLD = 8_000  # Yerel sunucuya anlamlı veri (Zeek orig_bytes)
FULL_SPECTRUM_TIME_WINDOW_H = 72  # Disk–bulut olayları için gevşek zaman penceresi (saat)

CLOUD_ADMIN_ABUSE_KEYWORDS: tuple[str, ...] = (
    "attachrolepolicy",
    "attachuserpolicy",
    "putrolepolicy",
    "putuserpolicy",
    "createaccesskey",
    "createloginprofile",
    "assumerole",
    "createuser",
    "addusertogroup",
    "attachgrouppolicy",
    "putbucketpolicy",
    "roleassignments/write",
    "elevateaccess",
    "setdefaultpolicyversion",
    "administratoraccess",
    "iamfullaccess",
)

HAYABUSA_LATERAL_KEYWORDS: tuple[str, ...] = (
    "lateral movement",
    "lateral_movement",
    "pass the hash",
    "pth",
    "psexec",
    "wmiexec",
    "smbexec",
    "dcom",
    "winrm",
    "remote service",
    "powershell remoting",
    "scheduled task",
    "schtasks",
    "admin share",
    "tsclient",
    "qwinsta",
    "remote desktop",
    "mstsc",
    "t1021",
    "t1076",
    "t1570",
    "wmic process",
)

MOBILE_APK_IPA_SIGNALS: tuple[str, ...] = (
    ".apk",
    ".ipa",
    ".xapk",
    ".apkm",
    "play.google.com/store/apps",
    "apps.apple.com",
    "appgallery.huawei.com",
    "apkpure",
    "apkmirror",
    "fdroid.org",
)

ACCOUNT_TAKEOVER_LABEL = "BULUT HESABI ELE GEÇİRME (Account Takeover)"
ACCOUNT_TAKEOVER_RULE_TITLE = "BULUT HESABI ELE GEÇİRME (Account Takeover)"

FULL_SPECTRUM_LABEL = "TOPYEKÜN SİBER SALDIRI (DİZ-Tam-Saha-Pres)"
FULL_SPECTRUM_RULE_TITLE = "TOPYEKÜN SİBER SALDIRI — Telefon · PC · Yerel ağ · Bulut (Full-Spectrum)"

# Service Install anahtar kelimeleri (Chainsaw/Hayabusa)
SERVICE_INSTALL_KEYWORDS = (
    "service install", "service installation", "servis kurulumu",
    "7045", "4697", "sc.exe", "create service", "new service",
    "service created", "svc install",
)

# Security Bypass anahtar kelimeleri (Chainsaw/Hayabusa - süreç kurulumu anında)
SECURITY_BYPASS_KEYWORDS = (
    "security bypass", "güvenlik atlama", "uac bypass",
    "amsi bypass", "etw bypass", "defense evasion", "T1562",
    "audit disabled", "logging disabled", "log temizleme",
    "eventlog clear", "wevtutil", "clear-log", "bypass uac",
)


# Şüpheli süreç isimleri (Sigma/Chainsaw/Hayabusa kurallarında sık geçen)
SUSPICIOUS_PROCESS_NAMES = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "wmic.exe", "csc.exe", "installutil.exe", "reg.exe",
)

# Disk olaylarında "şüpheli süreç" vurgulayan anahtar kelimeler
SUSPICIOUS_KEYWORDS = (
    "suspicious", "malicious", "malware", "injection", "powershell",
    "encoded", "bypass", "execution", "script", "detection", "anomaly",
    "şüpheli", "zararlı", "enjeksiyon", "tespit",
)


def _extract_pids(text: str) -> set[int]:
    """Metinden PID değerlerini çıkarır (ProcessId, PID, NewProcessId vb.)."""
    if not text:
        return set()
    pids: set[int] = set()
    # ProcessId: 1234, NewProcessId=5678, PID 9012
    patterns = [
        r"(?:ProcessId|NewProcessId|ParentProcessId|PID)\s*[:=]\s*(\d+)",
        r"\bPID\s+(\d+)\b",
        r"process\s+id\s*[:=]\s*(\d+)",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            try:
                pids.add(int(m.group(1)))
            except (ValueError, IndexError):
                pass
    return pids


def _extract_process_names(text: str) -> set[str]:
    """Metinden süreç isimlerini çıkarır."""
    if not text:
        return set()
    text_lower = text.lower()
    found: set[str] = set()
    for name in SUSPICIOUS_PROCESS_NAMES:
        if name in text_lower:
            found.add(name)
    # Genel pattern: .exe ile biten kelimeler
    for m in re.finditer(r"([a-zA-Z0-9_-]+\.exe)", text, re.IGNORECASE):
        found.add(m.group(1).lower())
    return found


def _is_suspicious_disk_event(event: dict) -> bool:
    """Olay şüpheli süreç tespiti içeriyor mu?"""
    rt = (event.get("RuleTitle") or "").lower()
    dt = (event.get("Details") or "").lower()
    combined = rt + " " + dt
    return any(kw in combined for kw in SUSPICIOUS_KEYWORDS)


def _flatten_vol_tree(data: Any) -> list[dict]:
    """Volatility JSON tree yapısını düz listeye çevirir."""
    if isinstance(data, list):
        out = []
        for item in data:
            out.extend(_flatten_vol_tree(item))
        return out
    if isinstance(data, dict):
        if "__children" in data:
            children = data.get("__children", [])
            # Kendi alanları + çocukları
            row = {k: v for k, v in data.items() if k != "__children"}
            if row:
                out = [row]
            else:
                out = []
            for c in children:
                out.extend(_flatten_vol_tree(c))
            return out
        return [data]
    return []


def _get_malfind_pid_process(malfind_data: Any) -> list[tuple[int, str]]:
    """
    Malfind çıktısından (PID, ProcessName) listesi döner.
    Her bulgu = şüpheli bellek enjeksiyonu.
    """
    rows = _flatten_vol_tree(malfind_data)
    result: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    pid_keys = ("PID", "pid", "ProcessId", "Pid")
    process_keys = ("Process", "process", "ImageFileName", "Image", "ProcessName")

    for row in rows:
        if not isinstance(row, dict):
            continue
        pid_val = None
        for k in pid_keys:
            if k in row and row[k] is not None:
                try:
                    pid_val = int(row[k])
                    break
                except (ValueError, TypeError):
                    pass
        process_val = ""
        for k in process_keys:
            if k in row and row[k]:
                process_val = str(row[k]).strip().lower()
                break

        if pid_val is not None and (pid_val, process_val) not in seen:
            seen.add((pid_val, process_val))
            result.append((pid_val, process_val or "unknown"))

    return result


def _get_pslist_pid_to_process(pslist_data: Any) -> dict[int, str]:
    """Pslist çıktısından PID -> ProcessName eşlemesi."""
    rows = _flatten_vol_tree(pslist_data)
    mapping: dict[int, str] = {}
    pid_keys = ("PID", "pid", "ProcessId")
    process_keys = ("Process", "process", "ImageFileName", "Image", "Name")

    for row in rows:
        if not isinstance(row, dict):
            continue
        pid_val = None
        for k in pid_keys:
            if k in row and row[k] is not None:
                try:
                    pid_val = int(row[k])
                    break
                except (ValueError, TypeError):
                    pass
        process_val = ""
        for k in process_keys:
            if k in row and row[k]:
                process_val = str(row[k]).strip().lower()
                break
        if pid_val is not None:
            mapping[pid_val] = process_val or mapping.get(pid_val, "unknown")

    return mapping


def run_disk_memory_correlation(
    disk_events: list[dict],
    volatility_results: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Disk (Chainsaw/Hayabusa) ve bellek (Volatility malfind) bulgularını korelasyon yapar.

    Eğer:
    - Disk: Şüpheli süreç (örn. powershell.exe) tespit edilmiş
    - Bellek: Malfind aynı PID üzerinde şüpheli enjeksiyon bulmuş
    -> KESİNLEŞMİŞ TEHDİT (Disk + RAM Doğrulamalı)

    Cellebrite / Magnet AXIOM vaka bağlama mantığı.

    Args:
        disk_events: Normalize edilmiş timeline (Timestamp, Level, RuleTitle, Details)
        volatility_results: Volatility run_analysis çıktısı (results: pslist, malfind)

    Returns:
        (events_with_flags, confirmed_threats)
        - events_with_flags: confirmed_threat alanı eklenmiş olaylar
        - confirmed_threats: Raporun en başına konacak kesinleşmiş tehdit listesi
    """
    if not disk_events:
        return [], []

    volatility_results = volatility_results or {}
    results = volatility_results.get("results", {})

    malfind_raw = results.get("windows.malfind", results.get("windows.malfind.Malfind", []))
    pslist_raw = results.get("windows.pslist", results.get("windows.pslist.PsList", []))

    # Malfind: şüpheli bellek bulgusu olan (PID, Process) listesi
    malfind_pid_process = _get_malfind_pid_process(malfind_raw) if malfind_raw else []
    malfind_pids = {pid for pid, _ in malfind_pid_process}
    malfind_pid_to_process = dict(malfind_pid_process)

    # Pslist ile PID -> Process zenginleştir (malfind'de process boş olabilir)
    pid_to_process = _get_pslist_pid_to_process(pslist_raw) if pslist_raw else {}
    for pid, proc in malfind_pid_to_process.items():
        if not proc or proc == "unknown":
            pid_to_process[pid] = pid_to_process.get(pid, proc)
        else:
            pid_to_process[pid] = proc

    # Bellek tarafında şüpheli PID'ler
    suspicious_memory_pids = malfind_pids
    suspicious_memory_processes = {pid_to_process.get(pid, "").lower() for pid in suspicious_memory_pids}

    # Disk tarafında şüpheli olayları tara
    confirmed_threats: list[dict] = []
    events_with_flags: list[dict] = []

    for ev in disk_events:
        event = dict(ev)
        event["confirmed_threat"] = False

        if not _is_suspicious_disk_event(event):
            events_with_flags.append(event)
            continue

        # Disk olayından PID ve süreç ismi çıkar
        details = event.get("Details", "") or ""
        rule_title = event.get("RuleTitle", "") or ""
        combined = details + " " + rule_title

        disk_pids = _extract_pids(combined)
        disk_processes = _extract_process_names(combined)

        # Eşleşme: aynı PID veya aynı süreç ismi
        match_pid = bool(disk_pids & suspicious_memory_pids)
        match_process = bool(disk_processes & suspicious_memory_processes)

        # Süreç ismi eşleşmesi: disk'te "powershell" var, bellek'te PID X = powershell.exe
        for proc in disk_processes:
            if proc in suspicious_memory_processes:
                match_process = True
                break

        if match_pid or match_process:
            event["confirmed_threat"] = True
            # Kesinleşmiş tehdit kaydı (raporun en başına)
            ct = {
                "timestamp": (event.get("Timestamp") or "")[:19],
                "level": event.get("Level", "Critical"),
                "rule_title": event.get("RuleTitle", ""),
                "details": event.get("Details", ""),
                "label": "KESİNLEŞMİŞ TEHDİT (Disk + RAM Doğrulamalı)",
                "disk_pids": list(disk_pids),
                "memory_pids": list(suspicious_memory_pids & disk_pids) if disk_pids else list(suspicious_memory_pids)[:5],
            }
            confirmed_threats.append(ct)

        events_with_flags.append(event)

    return events_with_flags, confirmed_threats


def _is_external_ip(ip: str) -> bool:
    """IP dış ağda mı (RFC1918 değil)?"""
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return False
    parts = [int(x) for x in ip.split(".") if x.isdigit()]
    if len(parts) != 4:
        return False
    if parts[0] == 10:
        return False
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return False
    if parts[0] == 192 and parts[1] == 168:
        return False
    return True


def _is_private_lan_host(ip: str) -> bool:
    """Zeek hedefi: yerel ağ sunucusu (RFC1918, loopback değil)."""
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip.strip()):
        return False
    ip = ip.strip()
    if ip.startswith("127."):
        return False
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False


def _get_high_flow_external_ips(network_results: dict[str, Any]) -> list[tuple[str, int, int]]:
    """
    Ağ: Dışarıya yoğun veri akışı olan IP'ler (Zeek conn).
    Returns: [(external_ip, total_bytes, pid_or_0), ...]
    """
    conns = network_results.get("connections", [])
    if not conns:
        return []
    # Zeek: id.resp_h = hedef (dış IP), id.orig_h = kaynak, orig_bytes+resp_bytes
    # Exfil = bizden dışarı giden veri -> orig_bytes (client->server) yüksek, resp_h dış IP
    high_flow: dict[str, int] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        resp_h = c.get("id.resp_h") or c.get("resp_h") or c.get("ip.dst")
        orig_h = c.get("id.orig_h") or c.get("orig_h") or c.get("ip.src")
        if not resp_h or not _is_external_ip(str(resp_h)):
            continue
        try:
            ob = int(c.get("orig_bytes") or c.get("orig_ip_bytes") or 0)
        except (ValueError, TypeError):
            ob = 0
        try:
            rb = int(c.get("resp_bytes") or c.get("resp_ip_bytes") or 0)
        except (ValueError, TypeError):
            rb = 0
        total = ob + rb
        if total >= EXFIL_BYTE_THRESHOLD:
            high_flow[resp_h] = high_flow.get(resp_h, 0) + total
    return [(ip, total, 0) for ip, total in sorted(high_flow.items(), key=lambda x: -x[1])]


def _get_netscan_pid_for_ip(netscan_data: Any, external_ip: str) -> set[int]:
    """Volatility netscan: Bu external IP'ye bağlanan PID'ler."""
    rows = _flatten_vol_tree(netscan_data)
    pids: set[int] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        remote = str(r.get("RemoteAddress") or r.get("RemoteAddr") or "").strip()
        if remote == external_ip:
            pid = r.get("PID") or r.get("pid") or r.get("ProcessId")
            if pid is not None:
                try:
                    pids.add(int(pid))
                except (ValueError, TypeError):
                    pass
    return pids


def _is_service_install_event(event: dict) -> bool:
    """Disk: Service Install kaydı mı?"""
    rt = (event.get("RuleTitle") or "").lower()
    dt = (event.get("Details") or "").lower()
    combined = rt + " " + dt
    return any(kw in combined for kw in SERVICE_INSTALL_KEYWORDS)


def _is_security_bypass_event(event: dict) -> bool:
    """
    Disk: Süreç kurulumu anında 'Security Bypass' kaydı mı?
    Chainsaw/Hayabusa: UAC/AMSI/ETW bypass, log temizleme vb.
    """
    rt = (event.get("RuleTitle") or "").lower()
    dt = (event.get("Details") or "").lower()
    combined = rt + " " + dt
    return any(kw in combined for kw in SECURITY_BYPASS_KEYWORDS)


def _load_network_results_disk() -> dict[str, Any]:
    """network_analysis.json / analysis_summary yükler (run_triple_correlation ile aynı mantık)."""
    for path in (
        RESULTS / "network_analysis.json",
        RESULTS / "network" / "analysis_summary.json",
        RESULTS / "network" / "zeek_work" / "conn.log",
    ):
        if not path.exists():
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if path.suffix == ".json":
                data = json.loads(content)
                return data if isinstance(data, dict) else {"connections": data}
            conns = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    conns.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if conns:
                return {"connections": conns}
        except (json.JSONDecodeError, OSError):
            continue
    return {}


def _load_cloud_findings_disk() -> dict[str, Any]:
    p = RESULTS / "cloud_findings.json"
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _load_mobile_findings_disk() -> dict[str, Any]:
    p = RESULTS / "mobile_findings.json"
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def load_volatility_bundle_from_results(results_dir: Path | None = None) -> dict[str, Any] | None:
    """
    Bellek imajı olmadan ``data/results/volatility/*.json`` üzerinden Volatility sonuçları oluşturur.
    ``--case-study`` veya önceden dışa aktarılmış JSON ile korelasyon için.
    """
    base = Path(results_dir) if results_dir is not None else RESULTS
    vdir = base / "volatility"
    if not vdir.is_dir():
        return None
    out_results: dict[str, Any] = {}
    mapping = (
        ("windows_malfind.json", "windows.malfind"),
        ("windows_pslist.json", "windows.pslist"),
        ("windows_netscan.json", "windows.netscan"),
    )
    loaded = False
    for fname, key in mapping:
        path = vdir / fname
        if not path.exists():
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                out_results[key] = json.load(f)
            loaded = True
        except (json.JSONDecodeError, OSError):
            continue
    if not loaded:
        return None
    return {"success": True, "results": out_results}


def _http_client_ip(rec: dict) -> str:
    for key in ("id.orig_h", "orig_h", "client_ip", "ip.src", "src_ip"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _http_host_and_uri_blob(rec: dict) -> str:
    host = str(rec.get("host") or rec.get("server_name") or rec.get("http.host") or "").lower()
    uri = str(rec.get("uri") or rec.get("uri_original") or rec.get("http.uri") or "").lower()
    return f"{host} {uri}".strip()


def _http_targets_cloud_api(rec: dict) -> bool:
    blob = _http_host_and_uri_blob(rec)
    return bool(blob) and any(k in blob for k in CLOUD_API_HOST_KEYWORDS)


def _epoch_from_http_ts(rec: dict) -> float | None:
    ts = rec.get("ts") or rec.get("time") or rec.get("timestamp")
    if ts is None:
        s = str(rec.get("frame_time") or rec.get("ts") or "").strip()
        if not s:
            return None
        ts = s
    if isinstance(ts, (int, float)):
        t = float(ts)
        return t if t < 1e12 else t / 1000.0
    s = str(ts).strip()
    if not s:
        return None
    try:
        if re.match(r"^\d+\.?\d*$", s):
            t = float(s)
            return t if t < 1e12 else t / 1000.0
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            d = datetime.strptime(s[:26].replace("Z", ""), fmt.replace("Z", ""))
            return d.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.timestamp()
    except ValueError:
        return None


def _epoch_from_cloud_event(ev: dict) -> float | None:
    for key in ("Timestamp", "event_time"):
        raw = ev.get(key)
        if raw is None:
            continue
        s = str(raw).strip()
        if not s:
            continue
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00")[:32])
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.timestamp()
        except ValueError:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                d = datetime.strptime(s[:19], fmt).replace(tzinfo=timezone.utc)
                return d.timestamp()
            except ValueError:
                continue
    return None


def _within_times(a: float | None, b: float | None, window: float) -> bool:
    if a is None or b is None:
        return False
    return abs(a - b) <= window


def _suspicious_orig_ips_from_network(network_results: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in ("beaconing_suspicious", "dns_tunneling_suspicious"):
        for item in network_results.get(key) or []:
            if not isinstance(item, dict):
                continue
            ip = _http_client_ip(item) or str(item.get("id.orig_h") or item.get("orig_h") or "")
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                out.add(ip)
    return out


def _iter_all_cloud_events(cloud: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for bucket in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
        for ev in cloud.get(bucket) or []:
            if isinstance(ev, dict):
                out.append(ev)
    return out


def _cloud_event_is_privilege_change(ev: dict) -> bool:
    action = str(ev.get("Action") or ev.get("event_name") or ev.get("operation_name") or "").lower()
    if not action:
        return False
    return any(p in action for p in CLOUD_PRIVILEGE_ACTION_KEYWORDS)


def _cloud_source_ip(ev: dict) -> str:
    return str(ev.get("Source_IP") or ev.get("source_ip") or "").strip()


def _disk_event_is_ps_cloud_module(event: dict) -> bool:
    rt = (event.get("RuleTitle") or "").lower()
    dt = (event.get("Details") or "").lower()
    combined = rt + " " + dt
    return any(kw in combined for kw in PS_CLOUD_MODULE_KEYWORDS)


def _epoch_from_disk_event(event: dict) -> float | None:
    ts = str(event.get("Timestamp") or "").strip()
    if len(ts) < 10:
        return None
    try:
        d = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return d.timestamp()
    except ValueError:
        try:
            d = datetime.fromisoformat(ts.replace(" ", "T")[:32])
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.timestamp()
        except ValueError:
            return None


def run_cloud_account_takeover_correlation(
    disk_events: list[dict],
    network_results: dict[str, Any] | None = None,
    cloud_findings: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    DİZ Akıllı Bulut-Yerel Korelasyon (yüksek öncelik).

    Koşullar (tümü):
    1. Ağ (Zeek/Tshark HTTP): Şüpheli veya yoğun kaynak IP'den AWS/Azure API uçlarına çok sayıda istek
    2. Bulut (AWS/Azure): Aynı kaynak IP ile saniye düzeyinde hizalı **yetki / kimlik** değişimi
    3. Disk (Chainsaw): Yerelde **PowerShell Cloud Module** (AWS/Azure cmdlet) kullanımı

    DİZ Kararı: BULUT HESABI ELE GEÇİRME (Account Takeover).

    Not: ``network_analysis.json`` KVKK maskeli üretildiyse tüm IP'ler aynı tokene düşebilir;
    tek çıkış IP'li senaryoda korelasyon yine tetiklenir.
    """
    if not disk_events:
        return [], []

    nr = dict(network_results) if network_results else _load_network_results_disk()
    if not nr.get("http_traffic") and not nr.get("http_requests"):
        alt = _load_network_results_disk()
        for k, v in alt.items():
            if v and not nr.get(k):
                nr[k] = v

    http_traffic = list(nr.get("http_traffic") or nr.get("http_requests") or [])
    cloud = cloud_findings if cloud_findings is not None else _load_cloud_findings_disk()

    suspicious_orig = _suspicious_orig_ips_from_network(nr)
    # İstemci IP -> (cloud API istek zamanları, sayım)
    per_client_times: dict[str, list[float]] = {}
    per_client_count: dict[str, int] = {}

    for rec in http_traffic:
        if not isinstance(rec, dict) or not _http_targets_cloud_api(rec):
            continue
        cip = _http_client_ip(rec)
        if not cip:
            continue
        ep = _epoch_from_http_ts(rec)
        per_client_count[cip] = per_client_count.get(cip, 0) + 1
        if ep is not None:
            per_client_times.setdefault(cip, []).append(ep)

    ps_cloud_disk_events = [e for e in disk_events if _disk_event_is_ps_cloud_module(e)]
    if not ps_cloud_disk_events:
        return list(disk_events), []

    cloud_priv_events = [e for e in _iter_all_cloud_events(cloud) if _cloud_event_is_privilege_change(e)]
    if not cloud_priv_events:
        return list(disk_events), []

    takeover_threats: list[dict] = []
    events_out = [dict(e) for e in disk_events]
    for e in events_out:
        e.setdefault("account_takeover_threat", False)

    seen_keys: set[tuple[str, str, str]] = set()

    for client_ip, n_req in per_client_count.items():
        if client_ip in suspicious_orig:
            if n_req < CLOUD_API_REQUESTS_WITH_BEACON:
                continue
        elif n_req < CLOUD_API_REQUESTS_HEAVY:
            continue

        http_epochs = per_client_times.get(client_ip) or []

        for cev in cloud_priv_events:
            cip_cloud = _cloud_source_ip(cev)
            if not cip_cloud or cip_cloud != client_ip:
                continue
            c_epoch = _epoch_from_cloud_event(cev)
            if http_epochs and c_epoch is not None:
                net_ok = any(_within_times(c_epoch, h, CLOUD_NET_TIME_WINDOW_SEC) for h in http_epochs)
            elif http_epochs and c_epoch is None:
                net_ok = True
            elif not http_epochs and n_req >= CLOUD_API_REQUESTS_HEAVY:
                net_ok = True
            else:
                net_ok = False

            if not net_ok:
                continue

            disk_ok = False
            disk_match: dict[str, Any] | None = None
            for dev in ps_cloud_disk_events:
                de = _epoch_from_disk_event(dev)
                if de is None:
                    continue
                if c_epoch is not None and _within_times(de, c_epoch, DISK_CLOUD_TIME_WINDOW_SEC):
                    disk_ok = True
                    disk_match = dev
                    break
                if http_epochs and any(
                    _within_times(de, h, DISK_CLOUD_TIME_WINDOW_SEC) for h in http_epochs
                ):
                    disk_ok = True
                    disk_match = dev
                    break

            if not disk_ok:
                continue

            action = str(
                cev.get("Action") or cev.get("event_name") or cev.get("operation_name") or "?"
            )[:160]
            sk = (client_ip, action[:80], str(cev.get("event_time") or cev.get("Timestamp") or ""))
            if sk in seen_keys:
                continue
            seen_keys.add(sk)

            disk_rule = (disk_match or {}).get("RuleTitle", "") if disk_match else ""
            takeover_threats.append(
                {
                    "timestamp": str(cev.get("Timestamp") or cev.get("event_time") or "")[:32],
                    "level": "Critical",
                    "rule_title": ACCOUNT_TAKEOVER_RULE_TITLE,
                    "label": ACCOUNT_TAKEOVER_LABEL,
                    "details": (
                        f"Kaynak_IP={client_ip} | Bulut_aksiyon={action} | HTTP_istek_sayısı≈{n_req} | "
                        f"Disk={disk_rule[:120]}"
                    ),
                    "source_ip": client_ip,
                    "cloud_action": action,
                    "http_requests_to_cloud_api": n_req,
                    "beaconing_client": client_ip in suspicious_orig,
                    "disk_evidence_title": disk_rule,
                    "technical_summary": (
                        f"Zeek/Tshark: {client_ip} adresinden AWS/Azure yönetim ve API uçlarına yoğun HTTP trafiği "
                        f"({n_req}+ istek). Aynı IP üzerinden bulutta yetki değişimi: {action}. "
                        f"Yerel günlüklerde PowerShell bulut modülü / cmdlet kullanımı (Chainsaw): {disk_rule or 'ilgili olay'}. "
                        "DİZ Kararı: BULUT HESABI ELE GEÇİRME (Account Takeover) — en yüksek öncelik."
                    ),
                }
            )

    matched_disk_titles = {
        th.get("disk_evidence_title")
        for th in takeover_threats
        if th.get("disk_evidence_title")
    }
    for ev in events_out:
        if not _disk_event_is_ps_cloud_module(ev):
            continue
        if ev.get("RuleTitle") in matched_disk_titles:
            ev["account_takeover_threat"] = True

    for th in reversed(takeover_threats):
        events_out.insert(
            0,
            {
                "Timestamp": (th.get("timestamp") or "")[:19],
                "Level": "Critical",
                "RuleTitle": ACCOUNT_TAKEOVER_RULE_TITLE,
                "Details": th.get("details", ""),
                "account_takeover_threat": True,
                "confirmed_threat": True,
                "high_alert": True,
                "exfiltration_threat": False,
            },
        )

    return events_out, takeover_threats


def run_triple_correlation(
    disk_events: list[dict],
    volatility_results: dict[str, Any] | None = None,
    network_results: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    DİZ Akıllı Mantık - Üçlü Korelasyon (Triple Cross-Check):
    Ağ + Bellek + Disk -> KRİTİK VERİ SIZINTISI

    Koşullar (hepsi sağlanmalı):
    1. Ağ (Zeek): Şüpheli IP'ye veri çıkışı (yoğun akış)
    2. Bellek (Volatility): O bağlantıyı kuran process gizli (hidden) modül içeriyor (malfind)
    3. Disk (Chainsaw): O process'in kurulduğu an loglarda 'Service Install' VEYA 'Security Bypass'

    Türkiye'deki hiçbir açık kaynak projede bu seviyede sunulmamıştır.

    Returns:
        (events_with_exfiltration_flag, exfiltration_threats)
    """
    if not disk_events:
        return disk_events, []

    volatility_results = volatility_results or {}
    network_results = network_results or {}

    # Network yoksa dosyadan yükle
    if not network_results.get("connections"):
        for path in [
            RESULTS / "network_analysis.json",
            RESULTS / "network" / "analysis_summary.json",
            RESULTS / "network" / "zeek_work" / "conn.log",
        ]:
            if not path.exists():
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if path.suffix == ".json":
                    data = json.loads(content)
                    network_results = data if isinstance(data, dict) else {"connections": data}
                    break
                # Zeek conn.log JSON (satır satır)
                conns = []
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        conns.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                if conns:
                    network_results = {"connections": conns}
                    break
            except (json.JSONDecodeError, OSError):
                continue

    results = volatility_results.get("results", {})
    malfind_raw = results.get("windows.malfind", results.get("windows.malfind.Malfind", []))
    netscan_raw = results.get("windows.netscan", results.get("windows.netscan.NetScan", []))

    malfind_pids = {pid for pid, _ in _get_malfind_pid_process(malfind_raw)} if malfind_raw else set()
    high_flow_ips = _get_high_flow_external_ips(network_results)
    service_install_timestamps = {
        (e.get("Timestamp") or "")[:16]
        for e in disk_events
        if _is_service_install_event(e)
    }
    security_bypass_timestamps = {
        (e.get("Timestamp") or "")[:16]
        for e in disk_events
        if _is_security_bypass_event(e)
    }
    # Disk doğrulaması: Service Install VEYA Security Bypass
    disk_confirm_timestamps = service_install_timestamps | security_bypass_timestamps

    exfiltration_threats: list[dict] = []
    events_with_flags = []
    seen_exfil_key: set[tuple[str, int]] = set()

    for ev in disk_events:
        event = dict(ev)
        event["exfiltration_threat"] = False

        # DİZ Kararı: Ağ (şüpheli IP veri çıkışı) + Bellek (gizli modül) + Disk (Service Install VEYA Security Bypass)
        for ext_ip, total_bytes, _ in high_flow_ips:
            pids_for_ip = _get_netscan_pid_for_ip(netscan_raw, ext_ip) if netscan_raw else set()
            hidden_pids = pids_for_ip & malfind_pids
            if not hidden_pids:
                continue
            if not disk_confirm_timestamps:
                continue  # Disk tarafında doğrulama yoksa üçlü tamamlanmaz

            key = (ext_ip, total_bytes)
            if key not in seen_exfil_key:
                seen_exfil_key.add(key)
                disk_reason = []
                if service_install_timestamps:
                    disk_reason.append("Service Install")
                if security_bypass_timestamps:
                    disk_reason.append("Security Bypass")
                exfiltration_threats.append({
                    "timestamp": list(disk_confirm_timestamps)[0][:19] if disk_confirm_timestamps else "",
                    "level": "Critical",
                    "rule_title": "KRİTİK VERİ SIZINTISI (EXFILTRATION)",
                    "details": f"Dış IP: {ext_ip} | {total_bytes:,} byte | Gizli PID: {hidden_pids}",
                    "label": "KRİTİK VERİ SIZINTISI (EXFILTRATION)",
                    "external_ip": ext_ip,
                    "total_bytes": total_bytes,
                    "hidden_pids": list(hidden_pids),
                    "disk_evidence": " + ".join(disk_reason),
                    "technical_summary": (
                        f"Dış IP {ext_ip} adresine {total_bytes:,} byte veri çıkışı tespit edildi. "
                        f"Bağlantıyı kuran süreç(ler) gizli (hidden) modül içeriyor (PID: {', '.join(map(str, hidden_pids))}). "
                        f"Olay günlüklerinde süreç kurulumu anında {' ve '.join(disk_reason)} kaydı mevcut. "
                        "DİZ Kararı: KRİTİK VERİ SIZINTISI. Türkiye Siber Güvenlik Standartlarına göre risk yüksektir."
                    ),
                })

            # Bu event doğrulama kapsamındaysa işaretle
            ev_ts = (event.get("Timestamp") or "")[:16]
            if _is_service_install_event(event) or _is_security_bypass_event(event) or ev_ts in disk_confirm_timestamps:
                event["exfiltration_threat"] = True

        events_with_flags.append(event)

    # Exfiltration bulgularını timeline'a sentetik olay olarak ekle (en üste)
    for et in exfiltration_threats:
        events_with_flags.insert(0, {
            "Timestamp": et["timestamp"],
            "Level": "Critical",
            "RuleTitle": et["rule_title"],
            "Details": et["details"],
            "exfiltration_threat": True,
            "confirmed_threat": True,
            "high_alert": True,
        })

    return events_with_flags, exfiltration_threats


def _iter_cloud_buckets(cloud: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for bucket in ("critical_events", "bulut_sizintisi", "hybrid_attacks"):
        for e in cloud.get(bucket) or []:
            if isinstance(e, dict):
                out.append(e)
    return out


def _cloud_event_is_admin_abuse(ev: dict) -> bool:
    action = str(ev.get("Action") or ev.get("event_name") or ev.get("operation_name") or "").lower()
    return any(k in action for k in CLOUD_ADMIN_ABUSE_KEYWORDS)


def _mobile_suspicious_apk_ipa(mobile: dict[str, Any]) -> tuple[bool, list[str]]:
    """APK / IPA / mağaza indirme izi — şüpheli mobil yükleme adayı."""
    reasons: list[str] = []
    for h in mobile.get("browser_history") or []:
        if not isinstance(h, dict):
            continue
        url = str(h.get("url") or "").lower()
        if any(sig in url for sig in MOBILE_APK_IPA_SIGNALS):
            reasons.append(f"tarayıcı:{url[:140]}")
    for m in (mobile.get("whatsapp_messages") or [])[:9000]:
        if not isinstance(m, dict):
            continue
        b = str(m.get("body") or "").lower()
        if ".apk" in b or ".ipa" in b:
            reasons.append(f"whatsapp:{b[:100]}")
            break
        if "apk" in b and ("indir" in b or "download" in b or "yükl" in b):
            reasons.append(f"whatsapp:{b[:100]}")
            break
    return (len(reasons) > 0), reasons[:15]


def _zeek_lan_server_exfil_list(network_results: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Yerel ağ (RFC1918) sunucusuna istemciden anlamlı uplink — C2 / sızdırma adayı (Zeek conn).
    """
    conns = network_results.get("connections") or []
    acc: dict[tuple[str, str], int] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        resp = str(c.get("id.resp_h") or c.get("resp_h") or c.get("ip.dst") or "").strip()
        orig = str(c.get("id.orig_h") or c.get("orig_h") or c.get("ip.src") or "").strip()
        if not orig or not _is_private_lan_host(resp):
            continue
        try:
            ob = int(c.get("orig_bytes") or c.get("orig_ip_bytes") or 0)
        except (ValueError, TypeError):
            ob = 0
        try:
            rb = int(c.get("resp_bytes") or c.get("resp_ip_bytes") or 0)
        except (ValueError, TypeError):
            rb = 0
        if ob < INTERNAL_LAN_EXFIL_BYTE_THRESHOLD:
            continue
        key = (orig, resp)
        acc[key] = acc.get(key, 0) + ob + rb
    rows = [
        {"orig_h": a, "internal_server_ip": b, "total_bytes": sz, "direction": "client->LAN_server"}
        for (a, b), sz in sorted(acc.items(), key=lambda x: -x[1])
    ]
    return rows


def _disk_lateral_movement_hits(disk_events: list[dict]) -> list[dict]:
    """Hayabusa + Chainsaw birleşik zaman çizgisi — lateral movement anahtar kelimeleri."""
    hits: list[dict] = []
    for e in disk_events:
        if not isinstance(e, dict):
            continue
        blob = f"{(e.get('RuleTitle') or '')} {(e.get('Details') or '')}".lower()
        if any(kw in blob for kw in HAYABUSA_LATERAL_KEYWORDS):
            hits.append(e)
    return hits


def _lateral_cloud_time_aligned(lateral: list[dict], cloud_subset: list[dict], window_sec: float) -> bool:
    if not lateral or not cloud_subset:
        return False
    le = [t for t in (_epoch_from_disk_event(e) for e in lateral) if t is not None]
    ce = [t for t in (_epoch_from_cloud_event(e) for e in cloud_subset) if t is not None]
    if not le or not ce:
        return True
    return any(abs(a - b) <= window_sec for a in le for b in ce)


def run_full_spectrum_correlation(
    disk_events: list[dict],
    network_results: dict[str, Any] | None = None,
    cloud_findings: dict[str, Any] | None = None,
    mobile_findings: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    DİZ-Tam-Saha-Pres — beş sütunlu vaka bağlama:

    1. **Mobil:** Şüpheli APK/IPA / mağaza indirme izi (`mobile_findings.json`)
    2. **Ağ (Zeek):** Yerel ağ sunucusuna (RFC1918 hedef) yüksek uplink — veri sızdırma adayı
    3. **Bulut:** Aynı kaynak IP'nin AWS/Azure üzerinde admin / ayrıcalık API kullanımı (CloudTrail / Activity)
    4. **Disk:** Windows günlüklerinde lateral movement (Hayabusa + Chainsaw zaman damgalarıyla hizalı)

    DİZ Kararı: **TOPYEKÜN SİBER SALDIRI** — Telefon · PC · Bulut tek rapor altında.

    Not: IP eşlemesi Zeek `id.orig_h` ile bulut `source_ip` arasında yapılır (NAT çıkışı aynı olduğunda).
    """
    if not disk_events:
        return [], []

    nr = dict(network_results) if network_results else _load_network_results_disk()
    if not nr.get("connections"):
        alt = _load_network_results_disk()
        for k, v in alt.items():
            if v and not nr.get(k):
                nr[k] = v

    cloud = cloud_findings if cloud_findings is not None else _load_cloud_findings_disk()
    mobile = mobile_findings if mobile_findings is not None else _load_mobile_findings_disk()

    mobile_ok, mobile_reasons = _mobile_suspicious_apk_ipa(mobile)
    lan_flows = _zeek_lan_server_exfil_list(nr)
    lateral_hits = _disk_lateral_movement_hits(disk_events)

    admin_by_ip: dict[str, list[dict[str, Any]]] = {}
    for ev in _iter_cloud_buckets(cloud):
        if not _cloud_event_is_admin_abuse(ev):
            continue
        ip = _cloud_source_ip(ev)
        if not ip:
            continue
        admin_by_ip.setdefault(ip, []).append(ev)

    threats: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    window_sec = float(FULL_SPECTRUM_TIME_WINDOW_H * 3600)

    for flow in lan_flows:
        orig = flow["orig_h"]
        if orig not in admin_by_ip:
            continue
        csubset = admin_by_ip[orig]
        if not _lateral_cloud_time_aligned(lateral_hits, csubset, window_sec):
            continue
        if not mobile_ok:
            continue
        key = (orig, flow["internal_server_ip"], str(csubset[0].get("event_time") or "")[:24])
        if key in seen:
            continue
        seen.add(key)
        lateral_sample = (lateral_hits[0].get("RuleTitle") or "")[:120]
        cloud_act = str(
            csubset[0].get("Action") or csubset[0].get("event_name") or csubset[0].get("operation_name") or "admin API"
        )[:160]
        threats.append(
            {
                "timestamp": str(csubset[0].get("Timestamp") or csubset[0].get("event_time") or "")[:32],
                "level": "Critical",
                "rule_title": FULL_SPECTRUM_RULE_TITLE,
                "label": FULL_SPECTRUM_LABEL,
                "details": (
                    f"IP={orig} | LAN_hedef={flow['internal_server_ip']} | "
                    f"zeek_bytes≈{flow['total_bytes']} | bulut={cloud_act[:80]}"
                ),
                "source_ip": orig,
                "internal_server_ip": flow["internal_server_ip"],
                "lan_exfil_bytes": flow["total_bytes"],
                "cloud_admin_actions_sample": cloud_act,
                "mobile_signals": mobile_reasons[:8],
                "lateral_log_sample": lateral_sample,
                "technical_summary": (
                    "DİZ-Tam-Saha-Pres: (1) Mobil yedekte APK/IPA veya mağaza tabanlı şüpheli yükleme izi. "
                    f"(2) Zeek: aynı uç ({orig}) yerel ağ sunucusuna ({flow['internal_server_ip']}) "
                    f"~{flow['total_bytes']:,} bayt aktarım. "
                    f"(3) Bulut: bu IP ile AWS/Azure üzerinde ayrıcalık/yönetim API’si ({cloud_act}). "
                    f"(4) Disk (Hayabusa/Chainsaw): lateral movement — örnek kural: {lateral_sample or '…'}. "
                    "DİZ Kararı: **TOPYEKÜN SİBER SALDIRI** — telefon, kurumsal uç nokta ve bulut aynı operasyon "
                    "zincirinde; tüm kanıtlar `correlation_results.json` ve HTML özette birleştirilmelidir."
                ),
                "evidence_bundle": {
                    "mobile_findings_path": str(RESULTS / "mobile_findings.json"),
                    "network_analysis_path": str(RESULTS / "network_analysis.json"),
                    "cloud_findings_path": str(RESULTS / "cloud_findings.json"),
                    "disk_timeline": "Hayabusa + Chainsaw (main.py birleşik)",
                },
            }
        )

    events_out = [dict(e) for e in disk_events]
    for e in events_out:
        e.setdefault("full_spectrum_threat", False)

    if threats:
        matched_titles = {str(x.get("RuleTitle") or "") for x in lateral_hits if x.get("RuleTitle")}
        for e in events_out:
            if str(e.get("RuleTitle") or "") in matched_titles:
                e["full_spectrum_threat"] = True

    for th in reversed(threats):
        events_out.insert(
            0,
            {
                "Timestamp": (th.get("timestamp") or "")[:19],
                "Level": "Critical",
                "RuleTitle": FULL_SPECTRUM_RULE_TITLE,
                "Details": th.get("details", ""),
                "full_spectrum_threat": True,
                "account_takeover_threat": False,
                "confirmed_threat": True,
                "high_alert": True,
                "exfiltration_threat": False,
            },
        )

    return events_out, threats


def merge_timeline_with_confirmed_threats(
    events: list[dict],
    confirmed_threats: list[dict],
) -> list[dict]:
    """
    Kesinleşmiş tehditleri timeline'ın en başına ekler.
    Rapor sıralaması: Önce KESİNLEŞMİŞ TEHDİT, sonra diğer olaylar.
    """
    if not confirmed_threats:
        return events

    # confirmed_threat=True olanları zaten events içinde; onları en başa taşı
    confirmed_events = [e for e in events if e.get("confirmed_threat")]
    other_events = [e for e in events if not e.get("confirmed_threat")]

    # confirmed_threats'tan gelen ayrı kayıtları da ekleyebiliriz (özet kartları için)
    # Şimdilik sadece sıralama: önce kesinleşmiş, sonra diğerleri
    return confirmed_events + other_events


def _alignment_collect_entries(
    disk_timeline: list[dict],
    mobile_findings: dict[str, Any] | None,
    cloud_findings: dict[str, Any] | None,
    network_analysis: dict[str, Any] | None,
    volatility_results: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Disk / mobil / bulut / ağ / RAM (Volatility) zaman damgalarını tek listeye döker."""
    entries: list[dict[str, Any]] = []
    for e in disk_timeline:
        if not isinstance(e, dict):
            continue
        ep = _epoch_from_disk_event(e)
        if ep is None:
            continue
        entries.append(
            {
                "source": "disk",
                "epoch": ep,
                "label": str(e.get("RuleTitle") or "")[:120],
                "detail": str(e.get("Details") or "")[:200],
            }
        )
    mobile = mobile_findings or {}
    for m in (mobile.get("whatsapp_messages") or [])[:5000]:
        if not isinstance(m, dict):
            continue
        ep = _epoch_from_cloud_event({"event_time": m.get("timestamp_iso")})
        if ep is None:
            continue
        entries.append(
            {
                "source": "mobile",
                "epoch": ep,
                "label": "WhatsApp",
                "detail": str(m.get("body") or "")[:200],
            }
        )
    cf = cloud_findings or {}
    for ev in _iter_all_cloud_events(cf):
        ep = _epoch_from_cloud_event(ev)
        if ep is None:
            continue
        en = str(ev.get("event_name") or ev.get("Action") or "")[:80]
        entries.append(
            {
                "source": "cloud",
                "epoch": ep,
                "label": en or "cloud_event",
                "detail": str(ev.get("raw_summary") or ev.get("privilege_summary") or "")[:200],
            }
        )
    net = network_analysis or {}
    for c in (net.get("connections") or [])[:2000]:
        if not isinstance(c, dict):
            continue
        ep = _epoch_from_http_ts(c)
        if ep is None:
            continue
        rh = c.get("id.resp_h") or c.get("resp_h") or ""
        entries.append(
            {
                "source": "network",
                "epoch": ep,
                "label": f"conn->{rh}",
                "detail": f"orig_bytes={c.get('orig_bytes')}",
            }
        )
    vr = (volatility_results or {}).get("results") or {}
    for key, label in (("windows.netscan", "netscan"), ("windows.pslist", "pslist")):
        raw = vr.get(key)
        for row in _flatten_vol_tree(raw)[:300]:
            if not isinstance(row, dict):
                continue
            ts = row.get("CreateTime") or row.get("Timestamp")
            if not ts:
                continue
            ep = _epoch_from_disk_event({"Timestamp": str(ts).replace("T", " ")[:19]})
            if ep is None:
                ep = _epoch_from_cloud_event({"event_time": ts})
            if ep is None:
                continue
            proc = str(row.get("Process") or row.get("process") or "")
            entries.append(
                {
                    "source": "ram",
                    "epoch": ep,
                    "label": f"{label}:{proc}"[:100],
                    "detail": str(row.get("RemoteAddress") or row.get("PID") or "")[:120],
                }
            )
    return entries


def build_cross_source_timestamp_alignment(
    disk_timeline: list[dict],
    mobile_findings: dict[str, Any] | None = None,
    cloud_findings: dict[str, Any] | None = None,
    network_analysis: dict[str, Any] | None = None,
    volatility_results: dict[str, Any] | None = None,
    cluster_window_sec: float = 3900.0,
) -> dict[str, Any]:
    """
    Beş kaynak kanadı (Disk, RAM, Network, Cloud, Mobile) zaman damgalarını pencereli kümelere ayırır.
    ``summary_tr`` alanı DİZ-Analist / rapor gövdeleri için kısa Türkçe özet üretir.
    """
    entries = _alignment_collect_entries(
        disk_timeline,
        mobile_findings,
        cloud_findings,
        network_analysis,
        volatility_results,
    )
    entries.sort(key=lambda x: x["epoch"])
    clusters: list[dict[str, Any]] = []
    if not entries:
        return {
            "cluster_window_sec": cluster_window_sec,
            "entry_count": 0,
            "clusters": [],
            "ranked_by_coverage": [],
            "summary_tr": "Zaman hizalaması için yeterli damgalı olay yok.",
        }
    i = 0
    while i < len(entries):
        start_ep = entries[i]["epoch"]
        chunk = [entries[i]]
        j = i + 1
        while j < len(entries) and entries[j]["epoch"] - start_ep <= cluster_window_sec:
            chunk.append(entries[j])
            j += 1
        sources = sorted({e["source"] for e in chunk})
        t0 = datetime.fromtimestamp(start_ep, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        t1 = datetime.fromtimestamp(chunk[-1]["epoch"], tz=timezone.utc).strftime("%H:%M UTC")
        clusters.append(
            {
                "time_start_utc": t0,
                "time_end_utc": t1,
                "sources_present": sources,
                "wing_count": len(sources),
                "events": [
                    {
                        "source": e["source"],
                        "label": e["label"],
                        "detail": e["detail"],
                        "time_utc": datetime.fromtimestamp(e["epoch"], tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    }
                    for e in chunk[:40]
                ],
            }
        )
        i = j
    ranked = sorted(clusters, key=lambda c: (-c["wing_count"], -len(c["events"])))
    lines = []
    for c in ranked[:10]:
        lines.append(
            f"- {c['time_start_utc']} - {c['time_end_utc']}: "
            f"kanallar={','.join(c['sources_present'])} ({c['wing_count']} farkli kaynak)"
        )
    summary_tr = "Çok kaynaklı zaman kümesi (correlator):\n" + "\n".join(lines)
    return {
        "cluster_window_sec": cluster_window_sec,
        "entry_count": len(entries),
        "clusters": clusters,
        "ranked_by_coverage": ranked[:12],
        "summary_tr": summary_tr,
    }


# =============================================================================
# MITRE ATT&CK eşleştirme motoru
# Ortak analist dili: teknik + taktik etiketleri. Velociraptor VQL tabanlı sorgularda
# kullanılan taktik derinliğini DİZ zaman çizelgesine taşır (imza tabanlı heuristic).
# =============================================================================

# Enterprise sırası — ilerleme çubuğu: en ileri görülen taktik indeksi
MITRE_TACTICS_ORDER: list[tuple[str, str]] = [
    ("TA0043", "Keşif (Reconnaissance)"),
    ("TA0042", "Kaynak geliştirme (Resource Development)"),
    ("TA0001", "İlk erişim (Initial Access)"),
    ("TA0002", "Yürütme (Execution)"),
    ("TA0003", "Kalıcılık (Persistence)"),
    ("TA0004", "Yetki yükseltme (Privilege Escalation)"),
    ("TA0005", "Savunmadan kaçınma (Defense Evasion)"),
    ("TA0006", "Kimlik bilgisi erişimi (Credential Access)"),
    ("TA0007", "Ortam keşfi (Discovery)"),
    ("TA0008", "Yanal hareket (Lateral Movement)"),
    ("TA0009", "Toplama (Collection)"),
    ("TA0011", "Komuta ve kontrol (Command and Control)"),
    ("TA0010", "Sızıntı (Exfiltration)"),
    ("TA0040", "Etki (Impact)"),
]

MITRE_TACTIC_INDEX: dict[str, int] = {tid: i for i, (tid, _) in enumerate(MITRE_TACTICS_ORDER)}

# Her imza: herhangi bir alt dizge eşleşmesi yeterli (blob küçük harf)
MITRE_SIGNATURES: list[dict[str, Any]] = [
    {
        "any": ("brute force", "brute-force", "password spray", "password spraying", "failed logon", "failed login", "possible brute force"),
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
    },
    {
        "any": ("process injection", "malfind", "hollow process", "hollowprocess", "ldrload", "reflective dll", "memory injection", "thread hollow"),
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
    },
    {
        "any": ("lateral movement", "lateral movement", "pass the hash", "pass-the-hash", "pth", "wmic process", "dcom exec", "remote service", "scheduled task remote", "powershell remoting", "winrm"),
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
    },
    {
        "any": ("credential dumping", "lsass", "mimikatz", "sekurlsa", "sam hive", "ntds.dit", "/procdump", "comsvcs.dll"),
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
    },
    {
        "any": ("powershell", "encodedcommand", "-enc ", "invoke-expression", "iex(", "downloadstring"),
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    {
        "any": ("scheduled task", "schtasks", "schedule.task", "task scheduler", "\\currentversion\\run"),
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    {
        "any": ("new service", "service install", "persistence via service", "sc create", "createservice"),
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    {
        "any": ("uac bypass", "bypass uac", "amsi bypass", "tamper etw", "disable defender", "set-mppreference", "mpcmdrun"),
        "technique_id": "T1550.001",
        "technique_name": "Application Access Token / Defense evasion patterns",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
    },
    {
        "any": ("rdp ", "remote desktop", "terminal services", "port 3389"),
        "technique_id": "T1076",
        "technique_name": "Remote Desktop Protocol",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
    },
    {
        "any": ("dns tunnel", "dns tunneling", "beacon", "c2", "c&c", "command and control", "backconnect"),
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol (DNS)",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
    },
    {
        "any": ("web shell", "webshell", "aspx shell", "cmd.aspx"),
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    {
        "any": ("registry run", "run key", "currentversion\\runonce", "userinit", "winlogon shell"),
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    {
        "any": ("wmi ", "wmiprvse", "wmic ", "__filtertoconsumerbinding"),
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    {
        "any": ("cloudtrail", "sts.amazonaws.com", "assumerole", "s3 exfil", "bucket policy", "azure activity"),
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
    },
]


def _mitre_from_correlation_flags(event: dict[str, Any]) -> list[dict[str, str]]:
    """Korelasyon bayraklarından ek ATT&CK notları."""
    tags: list[dict[str, str]] = []
    if event.get("exfiltration_threat"):
        tags.append(
            {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic_id": "TA0010",
                "tactic_name": "Exfiltration",
            }
        )
    if event.get("account_takeover_threat"):
        tags.append(
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
            }
        )
    if event.get("full_spectrum_threat"):
        tags.append(
            {
                "technique_id": "T1195",
                "technique_name": "Supply Chain Compromise",
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
            }
        )
    if event.get("confirmed_threat"):
        # Disk + RAM korelasyon onayı — bellek süreç manipülasyonu bağlamı
        tags.append(
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection (korelasyon onaylı)",
                "tactic_id": "TA0004",
                "tactic_name": "Privilege Escalation",
            }
        )
    return tags


def match_mitre_tags_for_event(event: dict[str, Any]) -> list[dict[str, str]]:
    """
    Tek olay için MITRE teknik/taktik listesi (sıralı, tekilleştirilmiş).
    Hayabusa 'Brute Force' → T1110 / TA0006; Volatility enjeksiyon iması → T1055 / TA0004.
    """
    blob = (
        f"{event.get('RuleTitle', '')} {event.get('Details', '')} {event.get('Source', '')}"
    ).lower()
    by_id: dict[str, dict[str, str]] = {}
    for sig in MITRE_SIGNATURES:
        if not any(s in blob for s in sig["any"]):
            continue
        tid = str(sig["technique_id"])
        by_id[tid] = {
            "technique_id": tid,
            "technique_name": str(sig["technique_name"]),
            "tactic_id": str(sig["tactic_id"]),
            "tactic_name": str(sig["tactic_name"]),
        }
    for t in _mitre_from_correlation_flags(event):
        tid = t["technique_id"]
        if tid not in by_id:
            by_id[tid] = t
    out = list(by_id.values())

    def _sort_key(x: dict[str, str]) -> tuple[int, str]:
        idx = MITRE_TACTIC_INDEX.get(x.get("tactic_id", ""), -1)
        return (idx if idx >= 0 else 99, x.get("technique_id", ""))

    out.sort(key=_sort_key)
    if not out and event.get("high_alert"):
        out.append(
            {
                "technique_id": "T1562",
                "technique_name": "Impair Defenses (high alert — genel)",
                "tactic_id": "TA0005",
                "tactic_name": "Defense Evasion",
            }
        )
    return out


def enrich_timeline_with_mitre(events: list[dict[str, Any]]) -> None:
    """Zaman çizelgesi olaylarına ``mitre_tags`` ve ``mitre_primary`` ekler (yerinde)."""
    for e in events:
        if not isinstance(e, dict):
            continue
        tags = match_mitre_tags_for_event(e)
        e["mitre_tags"] = tags
        e["mitre_primary"] = tags[0] if tags else {}


def build_mitre_attack_progress_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Matris ilerlemesi: gözlenen taktikler içinde kurumsal sıralamada **en ileri** aşama.
    Rapor: 'Saldırgan şu an matrisin … aşamasında' metni + yüzde.
    """
    tactics_hit: dict[str, str] = {}
    technique_ids: set[str] = set()
    for e in events:
        if not isinstance(e, dict):
            continue
        for t in e.get("mitre_tags") or []:
            if not isinstance(t, dict):
                continue
            tac = str(t.get("tactic_id") or "")
            if tac and tac in MITRE_TACTIC_INDEX:
                tactics_hit[tac] = str(t.get("tactic_name") or "")
            tx = str(t.get("technique_id") or "")
            if tx:
                technique_ids.add(tx)
    tech_count = len(technique_ids)

    if not tactics_hit:
        return {
            "has_mitre": False,
            "furthest_tactic_id": "",
            "furthest_tactic_name": "",
            "furthest_stage_index": -1,
            "total_stages": len(MITRE_TACTICS_ORDER),
            "progress_percent": 0,
            "headline_plain": "MITRE ATT&CK eşlemesi: otomatik imza ile yeterli taktik çıkarılamadı; zaman çizelgesini manuel inceleyin.",
            "tactics_observed": [],
            "techniques_touched": 0,
            "attribution": "MITRE ATT&CK® — DİZ heuristik eşleme (Velociraptor taktik sorgu derinliği hedefi).",
        }

    furthest_id = max(tactics_hit.keys(), key=lambda x: MITRE_TACTIC_INDEX.get(x, -1))
    furthest_idx = MITRE_TACTIC_INDEX[furthest_id]
    display_name = tactics_hit.get(furthest_id) or next(
        (n for tid0, n in MITRE_TACTICS_ORDER if tid0 == furthest_id), furthest_id
    )
    total = len(MITRE_TACTICS_ORDER)
    progress_percent = min(100, int(round((furthest_idx + 1) / total * 100)))
    headline_plain = (
        f"Saldırgan şu an matrisin en ileri görülen aşamasında: «{display_name}» ({furthest_id}). "
        f"DİZ-MITRE motoru, zaman çizelgesinde bu taktik ve önceki aşamalara düşen izleri birleştirdi."
    )
    tactics_observed = [
        {"tactic_id": ta, "tactic_name": tactics_hit[ta], "stage_index": MITRE_TACTIC_INDEX[ta]}
        for ta in sorted(tactics_hit.keys(), key=lambda x: MITRE_TACTIC_INDEX.get(x, 0))
    ]
    return {
        "has_mitre": True,
        "furthest_tactic_id": furthest_id,
        "furthest_tactic_name": display_name,
        "furthest_stage_index": furthest_idx,
        "total_stages": total,
        "progress_percent": progress_percent,
        "headline_plain": headline_plain,
        "tactics_observed": tactics_observed,
        "techniques_touched": tech_count,
        "attribution": "MITRE ATT&CK® — DİZ heuristik eşleme (Velociraptor VQL tabanlı taktik analiz derinliği hedefi).",
    }
