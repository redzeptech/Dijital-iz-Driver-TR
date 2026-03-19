"""
Bulut Adli Biliş — AWS CloudTrail ve Azure Monitor / Activity Logs

- **AWS:** JSON / NDJSON / ``Records[]``; kritik süzme: ``StopLogging``, ``PutBucketPolicy``,
  ``CreateUser``, ``ConsoleLogin`` (**yalnızca MFA kanıtı olmayan** oturumlar — açık ``MFAUsed``
  veya ``mfaAuthenticated`` true ise kritik dışı).
- **Azure:** Activity Log — özellikle **sanal makine silme**, **rol ataması yazma**
  (``roleAssignments/write``), **ağ güvenlik grubu güncelleme** (NSG ``write`` / kural yazma).
- **Normalize:** Her olay ``core.utils.standardize_cloud_event_row`` ile uyumlu **Timestamp,
  User_Identity, Action, Source_IP, Status** sütunlarını içerir.

- Yerel dışa aktarım + isteğe bağlı **CloudTrail LookupEvents** (boto3).
- Ağ modülünün **şüpheli** IP listesi ile eşleşen oturumlar → **BULUT SIZINTISI**.

**Atıf:** Uzak uç kanıt disiplini ve toplu normalizasyon **GRR Rapid Response** ile;
tehdit sınıfı seçimi (ayrık kritik API’ler, oturum / ağ korelasyonu) **AWS GuardDuty** mantığıyla
yarışmayı hedefleyen tasarım (tamamen **yerel / offline** analiz).
"""

from __future__ import annotations

import json
import logging
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.module_manager import BaseModule
from core.utils import standardize_cloud_event_row

logger = logging.getLogger(__name__)

RESULTS_DEFAULT = _ROOT / "data" / "results"

IP_V4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)

# LookupEvents ile sık sorgulanan kritik EventName örnekleri (AWS)
AWS_LOOKUP_EVENT_NAMES: tuple[str, ...] = (
    "StopLogging",
    "CreateUser",
    "AuthorizeSecurityGroupIngress",
    "DeleteTrail",
    "ConsoleLogin",
    "AssumeRole",
)

# --- AWS CloudTrail: kritik / yüksek öncelikli eventName ---
AWS_CRITICAL_EVENT_NAMES: frozenset[str] = frozenset({
    "ConsoleLogin",
    "ConsoleSignin",
    "StopLogging",
    "DeleteTrail",
    "PutEventSelectors",
    "UpdateTrail",
    "DeleteBucket",
    "DeleteBucketPolicy",
    "PutBucketPolicy",
    "PutBucketPublicAccessBlock",
    "CreateLoginProfile",
    "CreateUser",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateAccessKey",
    "AssumeRole",
    "AssumeRoleWithWebIdentity",
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "ModifyVpcAttribute",
})

AWS_CRITICAL_PATTERN = re.compile(
    r"(ConsoleLogin|StopLogging|DeleteTrail|DeleteBucket|DisableLogging|DeleteObject|CreateUser|AuthorizeSecurityGroupIngress)$",
    re.I,
)

# --- Azure Activity Log: VM silme, NSG güncelleme vb. ---
AZURE_SUSPICIOUS_OPERATIONS: tuple[str, ...] = (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Resources/subscriptions/resourcegroups/delete",
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/join/action",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.KeyVault/vaults/delete",
)

AZURE_PRIVILEGE_SUBSTR: tuple[str, ...] = (
    "roleAssignments/write",
    "roleDefinitions/write",
    "elevateAccess",
    "networksecuritygroups/",
    "virtualmachines/delete",
)

# Azure: kullanıcı isteği — VM silme, rol ataması yazma, NSG güncelleme (GuardDuty-benzeri odak)
AZURE_THREAT_FOCUS_OPERATIONS: frozenset[str] = frozenset(
    {
        "microsoft.compute/virtualmachines/delete",  # Delete Virtual Machine
        "microsoft.authorization/roleassignments/write",  # Write RoleAssignments
        "microsoft.network/networksecuritygroups/write",  # Update Security Group
        "microsoft.network/networksecuritygroups/securityrules/write",
        "microsoft.network/networksecuritygroups/join/action",
    }
)


def _read_json_file(path: Path) -> Any:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def _read_json_ndjson(path: Path) -> list[dict]:
    out: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    out.append(row)
            except json.JSONDecodeError:
                continue
    return out


def _extract_cloudtrail_records(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        if "Records" in data and isinstance(data["Records"], list):
            return [x for x in data["Records"] if isinstance(x, dict)]
        if "eventName" in data or "EventName" in data:
            return [data]
    return []


def _aws_event_name(rec: dict) -> str:
    return str(rec.get("eventName") or rec.get("EventName") or "")


def _parse_additional_event_data(rec: dict) -> dict[str, Any]:
    aed = rec.get("additionalEventData")
    if isinstance(aed, dict):
        return aed
    if isinstance(aed, str) and aed.strip().startswith("{"):
        try:
            j = json.loads(aed)
            return j if isinstance(j, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _aws_login_used_mfa(rec: dict) -> bool:
    """CloudTrail kaydında MFA kullanımına dair açık kanıt var mı?"""
    aed = _parse_additional_event_data(rec)
    mfa = str(aed.get("MFAUsed") or aed.get("mfaUsed") or "").strip().lower()
    if mfa in ("yes", "true", "1"):
        return True
    ui = rec.get("userIdentity")
    if isinstance(ui, dict):
        sc = ui.get("sessionContext") or {}
        if isinstance(sc, dict):
            attr = sc.get("attributes") or {}
            if isinstance(attr, dict):
                val = str(attr.get("mfaAuthenticated") or "").strip().lower()
                if val == "true":
                    return True
    return False


def _aws_event_status(rec: dict) -> str:
    ec = rec.get("errorCode") or rec.get("ErrorCode")
    if ec:
        em = rec.get("errorMessage") or rec.get("ErrorMessage") or ""
        base = str(ec).strip()
        if em:
            return f"Failure|{base}: {str(em).strip()[:240]}"
        return f"Failure|{base}"
    return "Success"


def _aws_is_critical_event(rec: dict) -> bool:
    en = _aws_event_name(rec)
    if not en:
        return False
    # Konsol: yalnızca MFA'sız (veya MFA kanıtı olmayan) oturumlar kritik süzgeçte
    if en in ("ConsoleLogin", "ConsoleSignin"):
        return not _aws_login_used_mfa(rec)
    if en in AWS_CRITICAL_EVENT_NAMES:
        return True
    if AWS_CRITICAL_PATTERN.search(en):
        return True
    if "logging" in en.lower() and any(x in en.lower() for x in ("stop", "delete", "disable")):
        return True
    return False


def _aws_privilege_summary(rec: dict) -> str:
    """Saldırgan / işlemi yapanın hangi yetki ile davrandığını kısa açıklar."""
    ui = rec.get("userIdentity")
    if not isinstance(ui, dict):
        return ""
    utype = str(ui.get("type", "") or "")
    arn = str(ui.get("arn", "") or ui.get("Arn", "") or "")
    user_name = str(ui.get("userName", "") or ui.get("UserName", "") or "")
    if utype == "IAMUser" and user_name:
        return f"IAMUser → {user_name} (doğrudan kullanıcı anahtarı / konsol)"
    if utype == "Root" or arn.endswith(":root"):
        return "ROOT hesabı — tam yönetici (yüksek risk)"
    if utype == "AssumedRole":
        sc = ui.get("sessionContext") or {}
        issuer = (sc.get("sessionIssuer") or {}) if isinstance(sc, dict) else {}
        iname = str(issuer.get("userName") or issuer.get("Arn") or "")
        return f"AssumedRole → {iname[:120]} (geçici rol oturumu)"
    if utype == "AWSService":
        inv = str(ui.get("invokedBy") or "")
        return f"AWS servisi → {inv or arn[:80]}"
    if utype == "FederatedUser":
        return f"FederatedUser → {user_name or arn[:100]}"
    return f"{utype} {user_name or arn[:100]}".strip()


def _aws_source_ip(rec: dict) -> str:
    ip = rec.get("sourceIPAddress") or rec.get("SourceIPAddress")
    if ip and isinstance(ip, str):
        return ip.strip()
    ui = rec.get("userIdentity") or {}
    if isinstance(ui, dict):
        aid = ui.get("sessionContext", {}) or {}
        if isinstance(aid, dict):
            mfa = aid.get("sourceIdentity")
            if isinstance(mfa, str) and IP_V4.search(mfa):
                return mfa
    for key in ("sourceIpAddress", "clientIp"):
        v = rec.get(key)
        if isinstance(v, str) and IP_V4.search(v):
            return v.strip()
    return ""


def _apply_coreutils_cloud_schema(row: dict[str, Any]) -> None:
    """core.utils.standardize_cloud_event_row — Timestamp, User_Identity, Action, Source_IP, Status."""
    std = standardize_cloud_event_row(row)
    row.update(std)


def normalize_aws_cloudtrail_record(rec: dict) -> dict[str, Any]:
    ip = _aws_source_ip(rec)
    en = _aws_event_name(rec)
    st = _aws_event_status(rec)
    row: dict[str, Any] = {
        "cloud": "aws",
        "event_time": rec.get("eventTime") or rec.get("EventTime") or "",
        "event_name": en,
        "event_source": rec.get("eventSource") or rec.get("EventSource") or "",
        "source_ip": ip,
        "user_arn": (rec.get("userIdentity") or {}).get("arn")
        if isinstance(rec.get("userIdentity"), dict)
        else str(rec.get("userIdentity", "")),
        "privilege_summary": _aws_privilege_summary(rec),
        "raw_summary": f"{en} @ {ip}"[:500],
        "critical": _aws_is_critical_event(rec),
        "status_normalized": st,
    }
    _apply_coreutils_cloud_schema(row)
    return row


def _azure_operation_name(rec: dict) -> str:
    return str(
        rec.get("operationName")
        or rec.get("OperationName")
        or rec.get("properties", {}).get("operationName", "")
        if isinstance(rec.get("properties"), dict)
        else ""
    ).strip()


def _azure_event_status(rec: dict) -> str:
    st = rec.get("status") or rec.get("Status")
    if isinstance(st, dict):
        v = st.get("value") or st.get("Value")
        if v is not None and str(v).strip():
            return str(v).strip()
    props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
    for key in ("statusCode", "resultType", "status"):
        v = props.get(key) if props else None
        if v is not None and str(v).strip():
            return str(v).strip()
    return "Unknown"


def _azure_is_suspicious(rec: dict) -> bool:
    op = _azure_operation_name(rec).lower()
    if op in AZURE_THREAT_FOCUS_OPERATIONS:
        return True
    if not op:
        cat = str(rec.get("category") or rec.get("Category") or "").lower()
        if cat == "administrative":
            status = str(rec.get("status", {}).get("value", "")).lower() if isinstance(rec.get("status"), dict) else ""
            if status == "failed":
                return True
    for s in AZURE_SUSPICIOUS_OPERATIONS:
        if op == s.lower():
            return True
    for sub in AZURE_PRIVILEGE_SUBSTR:
        if sub.lower() in op:
            return True
    if "/delet" in op and "microsoft." in op:
        return True
    # "Delete Virtual Machine" benzeri tüketici ifadeleri
    if "virtualmachines" in op and "delete" in op:
        return True
    if "networksecuritygroups" in op and ("write" in op or "securityrules" in op):
        return True
    return False


def _azure_privilege_summary(rec: dict) -> str:
    op = _azure_operation_name(rec)
    auth = rec.get("authorization", {})
    if isinstance(auth, dict):
        role = auth.get("role") or auth.get("scope", "")
        if role:
            return f"{op[:80]} → yetki: {str(role)[:200]}"
    caller = _azure_source_ip(rec)
    return f"{op[:120]} (çağıran IP: {caller})"


def _azure_source_ip(rec: dict) -> str:
    props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
    for key in ("callerIpAddress", "clientIpAddress", "client_ip"):
        v = props.get(key) if props else rec.get(key)
        if isinstance(v, str) and v and v != "Not Applicable":
            return v.strip()
    http = props.get("httpRequest") if props else None
    if isinstance(http, dict):
        c = http.get("clientIpAddress")
        if isinstance(c, str):
            return c.strip()
    v = rec.get("callerIpAddress")
    if isinstance(v, str):
        return v.strip()
    return ""


def normalize_azure_activity_record(rec: dict) -> dict[str, Any]:
    ip = _azure_source_ip(rec)
    op = _azure_operation_name(rec)
    st = _azure_event_status(rec)
    row: dict[str, Any] = {
        "cloud": "azure",
        "event_time": rec.get("eventTimestamp") or rec.get("time") or rec.get("Time") or "",
        "operation_name": op,
        "resource_id": str(rec.get("resourceId") or rec.get("ResourceId") or ""),
        "source_ip": ip,
        "subscription_id": str(rec.get("subscriptionId") or ""),
        "privilege_summary": _azure_privilege_summary(rec),
        "raw_summary": f"{op} @ {ip}"[:500],
        "critical": _azure_is_suspicious(rec),
        "status_normalized": st,
    }
    _apply_coreutils_cloud_schema(row)
    return row


def fetch_cloudtrail_lookup_events(
    event_names: tuple[str, ...] | None = None,
    hours_back: int = 24,
    max_per_event: int = 50,
    region: str | None = None,
) -> tuple[list[dict], list[str]]:
    """
    AWS CloudTrail LookupEvents (API). Kimlik: ortam değişkenleri veya ~/.aws/credentials.

    Returns:
        (raw CloudTrail event dict listesi, hata mesajları)
    """
    errors: list[str] = []
    events_out: list[dict] = []
    names = event_names or AWS_LOOKUP_EVENT_NAMES

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        errors.append("boto3 yüklü değil: pip install boto3")
        return [], errors

    rgn = region or __import__("os").environ.get("AWS_REGION") or __import__("os").environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=max(1, hours_back))

    client = boto3.client("cloudtrail", region_name=rgn)
    for ename in names:
        try:
            req: dict[str, Any] = {
                "MaxResults": min(max_per_event, 50),
                "StartTime": start,
                "EndTime": now,
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": ename}],
            }
            resp = client.lookup_events(**req)
            for ev in resp.get("Events", []) or []:
                if not isinstance(ev, dict):
                    continue
                cte = ev.get("CloudTrailEvent")
                if cte and isinstance(cte, str):
                    try:
                        parsed = json.loads(cte)
                        if isinstance(parsed, dict):
                            events_out.append(parsed)
                            continue
                    except (json.JSONDecodeError, TypeError):
                        pass
                et = ev.get("EventTime")
                if hasattr(et, "isoformat"):
                    et_s = et.isoformat()
                else:
                    et_s = str(et) if et is not None else ""
                events_out.append(
                    {
                        "eventName": ev.get("EventName"),
                        "eventTime": et_s,
                        "eventID": ev.get("EventId"),
                    }
                )
        except (ClientError, BotoCoreError) as e:
            errors.append(f"LookupEvents {ename} ({rgn}): {e}")

    return events_out, errors


def fetch_azure_activity_logs_rest(
    subscription_id: str,
    hours_back: int = 24,
    api_version: str = "2015-04-01",
) -> tuple[list[dict], list[str]]:
    """
    Azure Activity Log — Management REST (ham JSON satırları).
    AZURE_ACCESS_TOKEN veya ARM token gerekir (Bearer).

    Örnek: `az account get-access-token --resource https://management.azure.com/`
    """
    import os

    errors: list[str] = []
    token = os.environ.get("AZURE_ACCESS_TOKEN") or os.environ.get("ARM_ACCESS_TOKEN")
    if not token:
        errors.append("AZURE_ACCESS_TOKEN yok; Azure canlı çekme atlandı.")
        return [], errors

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=max(1, hours_back))
    filt = (
        f"eventTimestamp ge '{start.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
        f"and eventTimestamp le '{end.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    )
    base = f"https://management.azure.com/subscriptions/{subscription_id}/providers/microsoft.insights/eventtypes/management/values"
    url = f"{base}?api-version={api_version}&$filter={quote(filt)}"

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as e:
        errors.append(f"Azure Activity HTTP {e.code}: {e.reason}")
        return [], errors
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        errors.append(f"Azure Activity: {e}")
        return [], errors

    rows = data.get("value", data) if isinstance(data, dict) else data
    if isinstance(rows, list):
        return [x for x in rows if isinstance(x, dict)], errors
    return [], errors


def _collect_records_from_path(evidence_path: Path) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    errors: list[str] = []
    paths: list[Path] = []

    if evidence_path.is_file():
        paths = [evidence_path]
    elif evidence_path.is_dir():
        for pat in (
            "**/*cloudtrail*.json",
            "**/*CloudTrail*.json",
            "**/*activity*.json",
            "**/*Activity*.json",
            "**/*azure*.json",
            "**/*.json",
        ):
            paths.extend(evidence_path.glob(pat))
        paths = sorted({p.resolve() for p in paths if p.is_file()})[:500]
    else:
        errors.append(f"Yol bulunamadi: {evidence_path}")
        return [], errors

    for p in paths:
        low = p.name.lower()
        try:
            if low.endswith(".json"):
                try:
                    data = _read_json_file(p)
                except json.JSONDecodeError:
                    for row in _read_json_ndjson(p):
                        records.append(row)
                    continue
                if isinstance(data, dict) and "Records" in data:
                    records.extend(_extract_cloudtrail_records(data))
                elif isinstance(data, dict) and "value" in data and isinstance(data["value"], list):
                    for item in data["value"]:
                        if isinstance(item, dict):
                            records.append(item)
                else:
                    records.extend(_extract_cloudtrail_records(data))
            else:
                records.extend(_read_json_ndjson(p))
        except OSError as e:
            errors.append(f"{p}: {e}")
        except json.JSONDecodeError as e:
            errors.append(f"{p}: JSON hatasi {e}")

    return records, errors


def _classify_and_normalize_record(rec: dict) -> dict[str, Any] | None:
    if _aws_event_name(rec):
        return normalize_aws_cloudtrail_record(rec)
    if (
        rec.get("operationName")
        or rec.get("OperationName")
        or (
            isinstance(rec.get("properties"), dict)
            and (rec.get("properties") or {}).get("operationName")
        )
    ):
        return normalize_azure_activity_record(rec)
    if str(rec.get("category") or "").lower() in ("administrative", "policy", "security"):
        return normalize_azure_activity_record(rec)
    return None


def _is_plausible_public_ip(ip: str) -> bool:
    if not ip or "*" in ip or "xxx" in ip.lower():
        return False
    if not IP_V4.fullmatch(ip.strip()):
        return False
    p = ip.split(".")
    try:
        o = [int(x) for x in p]
    except ValueError:
        return False
    if o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168):
        return False
    if o[0] == 127 or (o[0] == 169 and o[1] == 254):
        return False
    return True


def collect_suspicious_network_ips(results_dir: Path | None = None) -> set[str]:
    """
    Network modülünde 'şüpheli' sayılan IP'ler: beaconing, DNS tünelleme listeleri.
    (Tüm bağlantılardan IP toplamak yerine — BULUT SIZINTISI için daraltılmış küme.)
    """
    base = Path(results_dir) if results_dir else RESULTS_DEFAULT
    ips: set[str] = set()

    def add_from_obj(obj: Any) -> None:
        blob = json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj
        for m in IP_V4.finditer(blob):
            ip = m.group(0)
            if _is_plausible_public_ip(ip):
                ips.add(ip)

    p = base / "network_analysis.json"
    if p.exists():
        try:
            data = _read_json_file(p)
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            for key in ("beaconing_suspicious", "dns_tunneling_suspicious"):
                for item in data.get(key) or []:
                    add_from_obj(item)

    return ips


def collect_ips_from_network_results(results_dir: Path | None = None) -> set[str]:
    """Tüm ağ artefaktından IPv4 (geniş korelasyon)."""
    base = Path(results_dir) if results_dir else RESULTS_DEFAULT
    ips: set[str] = set()

    def add_from_obj(obj: Any) -> None:
        blob = json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj
        for m in IP_V4.finditer(blob):
            ips.add(m.group(0))

    p = base / "network_analysis.json"
    if p.exists():
        try:
            data = _read_json_file(p)
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            for key in ("connections", "beaconing_suspicious", "dns_tunneling_suspicious", "http_traffic"):
                add_from_obj(data.get(key) or [])

    p2 = base / "network" / "analysis_summary.json"
    if p2.exists():
        try:
            data = _read_json_file(p2)
            if isinstance(data, dict):
                for key in ("connections", "http_requests", "dns_queries"):
                    add_from_obj(data.get(key) or [])
        except (json.JSONDecodeError, OSError):
            pass

    return ips


def correlate_cloud_network(
    cloud_events: list[dict[str, Any]],
    suspicious_ips: set[str],
    all_network_ips: set[str],
) -> list[dict[str, Any]]:
    """
    - Şüpheli ağ IP + bulut oturumu → **BULUT SIZINTISI**
    - Diğer ağ örtüşmeleri → hybrid_attack (düşük öncelik)
    """
    enriched: list[dict[str, Any]] = []
    for ev in cloud_events:
        row = {**ev}
        ip = str(ev.get("source_ip") or "").strip()
        row["bulut_sizintisi"] = False
        row["bulut_sizintisi_reason"] = ""
        row["hybrid_attack"] = False
        row["hybrid_reason"] = ""

        if not ip:
            enriched.append(row)
            continue

        if ip in suspicious_ips:
            row["bulut_sizintisi"] = True
            row["bulut_sizintisi_reason"] = (
                "BULUT SIZINTISI: Oturum IP’si, Zeek/Tshark **şüpheli** listesinde "
                "(beaconing / DNS tünelleme)."
            )
            row["hybrid_attack"] = True
            row["hybrid_reason"] = row["bulut_sizintisi_reason"]
        elif ip in all_network_ips:
            row["hybrid_attack"] = True
            row["hybrid_reason"] = (
                f"Aynı IP ({ip}) bulut günlüğünde ve genel ağ çıktısında görüldü (şüpheli listeye düşmemiş)."
            )

        enriched.append(row)
    return enriched


def filter_critical_cloud_events(
    normalized: list[dict[str, Any]],
    include_non_critical_hybrid: bool = False,
) -> list[dict[str, Any]]:
    out = []
    for e in normalized:
        if e.get("critical"):
            out.append(e)
        elif include_non_critical_hybrid and (e.get("hybrid_attack") or e.get("bulut_sizintisi")):
            out.append(e)
    return out


class CloudForensicsModule(BaseModule):
    """
    AWS CloudTrail (dosya + LookupEvents) ve Azure Activity Logs.
    Yetki özeti + şüpheli ağ IP ile BULUT SIZINTISI korelasyonu.
    """

    name = "cloud"
    description = "AWS/Azure bulut günlükleri — kritik olaylar, yetki özeti, BULUT SIZINTISI (ağ şüpheli IP)"
    required_tools = []

    def execute(
        self,
        evidence_path: Path | None,
        output_dir: Path,
        results_dir: Path | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Args:
            evidence_path: CloudTrail / Azure JSON klasörü veya dosyası (API ile birlikte kullanılabilir)
            output_dir: cloud_findings.json
            results_dir: network_analysis.json kökü
            fetch_aws_lookup: True → CloudTrail LookupEvents (boto3)
            aws_lookup_hours: saat geriye
            aws_region: AWS bölge
            fetch_azure_rest: True → AZURE_ACCESS_TOKEN + azure_subscription_id gerekir
            azure_subscription_id: kwargs veya AZURE_SUBSCRIPTION_ID ortam değişkeni
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results_dir = Path(results_dir) if results_dir else RESULTS_DEFAULT

        raw_records: list[dict] = []
        errs: list[str] = []

        ev_path = Path(evidence_path) if evidence_path else None
        if ev_path and ev_path.exists():
            rec, e2 = _collect_records_from_path(ev_path)
            raw_records.extend(rec)
            errs.extend(e2)
        elif ev_path:
            errs.append(f"Kanıt yolu yok: {ev_path}")

        if kwargs.get("fetch_aws_lookup"):
            api_ev, api_err = fetch_cloudtrail_lookup_events(
                event_names=tuple(kwargs.get("aws_event_names") or AWS_LOOKUP_EVENT_NAMES),
                hours_back=int(kwargs.get("aws_lookup_hours", 24)),
                max_per_event=int(kwargs.get("aws_max_per_event", 50)),
                region=kwargs.get("aws_region"),
            )
            raw_records.extend(api_ev)
            errs.extend(api_err)

        if kwargs.get("fetch_azure_rest"):
            import os

            sub = kwargs.get("azure_subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID")
            if not sub:
                errs.append("fetch_azure_rest: AZURE_SUBSCRIPTION_ID eksik")
            else:
                az_rows, az_err = fetch_azure_activity_logs_rest(
                    str(sub),
                    hours_back=int(kwargs.get("azure_hours", 24)),
                )
                raw_records.extend(az_rows)
                errs.extend(az_err)

        normalized: list[dict[str, Any]] = []
        for rec in raw_records:
            n = _classify_and_normalize_record(rec)
            if n:
                normalized.append(n)

        suspicious = collect_suspicious_network_ips(results_dir)
        all_net = collect_ips_from_network_results(results_dir)
        correlated = correlate_cloud_network(normalized, suspicious, all_net)

        bulut_siz = [e for e in correlated if e.get("bulut_sizintisi")]
        hybrid_hits = [e for e in correlated if e.get("hybrid_attack")]
        critical_filtered = [e for e in correlated if e.get("critical")]

        out_path = output_dir / "cloud_findings.json"
        payload = {
            "success": True,
            "source_path": str(evidence_path) if evidence_path else "",
            "stats": {
                "raw_records_seen": len(raw_records),
                "normalized_events": len(normalized),
                "critical_events": len(critical_filtered),
                "bulut_sizintisi_events": len(bulut_siz),
                "hybrid_attack_events": len(hybrid_hits),
                "suspicious_network_ips": len(suspicious),
                "network_ips_for_correlation": len(all_net),
            },
            "critical_events": critical_filtered,
            "bulut_sizintisi": bulut_siz,
            "hybrid_attacks": hybrid_hits,
            "errors": errs,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        logger.info(
            "Cloud forensics: %s kritik, %s BULUT SIZINTISI → %s",
            len(critical_filtered),
            len(bulut_siz),
            out_path,
        )

        return {
            "success": True,
            "output_path": str(out_path),
            "cloud_findings_path": str(out_path),
            "critical_events": critical_filtered,
            "bulut_sizintisi": bulut_siz,
            "hybrid_attacks": hybrid_hits,
            "stats": payload["stats"],
            "errors": errs,
        }


def run_cloud_analysis(
    evidence_path: str | Path | None,
    output_dir: str | Path | None = None,
    results_dir: str | Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    mod = CloudForensicsModule()
    out = Path(output_dir) if output_dir else RESULTS_DEFAULT
    ep = Path(evidence_path) if evidence_path else None
    return mod.execute(ep, out, results_dir=Path(results_dir) if results_dir else None, **kwargs)
