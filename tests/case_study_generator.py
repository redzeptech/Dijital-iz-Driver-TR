#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dijital İz Sürücü — sentetik vaka üretici (analiz motoru / dashboard testi).

Şunları üretir (varsayılan: ``data/results``):

- **mobile_findings.json** — WhatsApp gövdesinde C2 IP’si (saldırgan mesajı).
- **network_analysis.json** — C2’ye ~500 MB orig_bytes ile Zeek-benzeri conn + beaconing şüphesi
  (``collect_suspicious_network_ips`` ile bulut korelasyonu için).
- **cloud_findings.json** — Aynı saatte Root + ``DeleteSnapshot``, kaynak IP = C2
  (``critical`` + BULUT SIZINTISI bayrakları).
- **hayabusa_output.json** — PowerShell + ``Invoke-WebRequest`` ile dış indirme.
- **volatility/windows_malfind.json** — Aynı PowerShell PID’sinde shellcode (malfind).
- **volatility/windows_pslist.json** — PID ↔ ``powershell.exe`` eşlemesi (korelasyon zenginleştirme).
- **volatility/windows_netscan.json** — C2 IP’ye giden TCP oturumu (üçlü exfil korelasyonu için).

Kullanım::

    python tests/case_study_generator.py
    python tests/case_study_generator.py --out-dir data/results

Uyarı: Üretilen dosyalar gerçek kanıt değildir; mevcut sonuçların üzerine yazar.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.utils import standardize_cloud_event_row  # noqa: E402

# RFC 5737/3849 dokümantasyon aralığı — özel ağ değil; korelasyon dış IP sayar.
C2_IP = "198.51.100.77"
# Senaryo ankrajı: tüm kanıtlar aynı UTC saat diliminde.
ANCHOR = datetime(2025, 3, 19, 13, 0, 0, tzinfo=timezone.utc)
EXFIL_BYTES = 500 * 1024 * 1024  # 500 MiB çıkış (orig_bytes odaklı)
PS_PID = 4840


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_compact(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def build_mobile_findings() -> dict[str, Any]:
    t_msg = ANCHOR.replace(minute=12, second=0)
    return {
        "success": True,
        "evidence_path": str(ROOT / "tests" / "synthetic_android_backup"),
        "stats": {
            "whatsapp_rows": 1,
            "sms_rows": 0,
            "contacts_rows": 0,
            "browser_history_rows": 0,
            "call_log_rows": 0,
            "location_rows": 0,
            "carving_rows": 0,
            "sqlite_files": 0,
        },
        "whatsapp_messages": [
            {
                "source_db": "/synthetic/msgstore.db",
                "jid": "905551234567@s.whatsapp.net",
                "sender_jid": "905551234567@s.whatsapp.net",
                "chat_jid": "905551234567@s.whatsapp.net",
                "body": (
                    f"Sunucu canlı. C2 Server IP: {C2_IP} — payload'u buraya POST et, "
                    "port 4444 açık."
                ),
                "timestamp_iso": t_msg.isoformat(),
                "from_me": False,
            }
        ],
        "sms_messages": [],
        "contacts": [],
        "browser_history": [],
        "call_logs": [],
        "locations": [],
        "carving_findings": [],
        "sqlite_files_scanned": 0,
        "filesystem_targets": {},
        "errors": [],
    }


def build_network_analysis() -> dict[str, Any]:
    """Zeek conn benzeri; exfil + beaconing listesinde aynı C2 IP (bulut korelasyonu)."""
    t_ts = ANCHOR.replace(minute=20, second=0)
    base_conn = {
        "id.orig_h": "192.168.1.50",
        "id.resp_h": C2_IP,
        "id.orig_p": 49152,
        "id.resp_p": 4444,
        "proto": "tcp",
        "service": "",
        "duration": 3600.0,
        "orig_bytes": EXFIL_BYTES,
        "resp_bytes": 65536,
        "conn_state": "S1",
        "ts": _iso_z(t_ts),
    }
    beacon = {
        **base_conn,
        "beaconing_suspicious": True,
        "unusual_port": 4444,
    }
    return {
        "http_traffic": [],
        "dns_queries": [],
        "dns_tunneling_suspicious": [],
        "connections": [base_conn],
        "beaconing_suspicious": [beacon],
        "suspicious_files": [],
    }


def build_cloud_findings() -> dict[str, Any]:
    t_cloud = ANCHOR.replace(minute=25, second=7)
    row: dict[str, Any] = {
        "cloud": "aws",
        "event_time": _iso_z(t_cloud),
        "event_name": "DeleteSnapshot",
        "event_source": "ec2.amazonaws.com",
        "source_ip": C2_IP,
        "user_arn": "arn:aws:iam::999888777666:root",
        "privilege_summary": "ROOT hesabı — tam yönetici (yüksek risk)",
        "raw_summary": f"DeleteSnapshot (EBS snapshot) from {C2_IP} as Root",
        "critical": True,
        "status_normalized": "Success",
    }
    row.update(standardize_cloud_event_row(row))
    row["bulut_sizintisi"] = True
    row["bulut_sizintisi_reason"] = (
        "BULUT SIZINTISI: Oturum IP’si, Zeek/Tshark **şüpheli** listesinde "
        "(beaconing / DNS tünelleme)."
    )
    row["hybrid_attack"] = True
    row["hybrid_reason"] = row["bulut_sizintisi_reason"]

    # UI ayrı listelerde dolaşır; gerçek pipeline ile uyumlu çoğaltma.
    event_copy = json.loads(json.dumps(row, ensure_ascii=False))
    payload = {
        "success": True,
        "source_path": str(ROOT / "tests" / "case_study_generator.py"),
        "stats": {
            "raw_records_seen": 1,
            "normalized_events": 1,
            "critical_events": 1,
            "bulut_sizintisi_events": 1,
            "hybrid_attack_events": 1,
            "suspicious_network_ips": 1,
            "network_ips_for_correlation": 1,
        },
        "critical_events": [event_copy],
        "bulut_sizintisi": [json.loads(json.dumps(row, ensure_ascii=False))],
        "hybrid_attacks": [json.loads(json.dumps(row, ensure_ascii=False))],
        "errors": [],
    }
    return payload


def build_hayabusa_disk_event() -> list[dict[str, Any]]:
    t_ps = ANCHOR.replace(minute=18, second=33)
    return [
        {
            "Timestamp": _iso_compact(t_ps),
            "Level": "high",
            "RuleTitle": "Suspicious PowerShell Download (Invoke-WebRequest)",
            "Details": (
                f"CommandLine contains Invoke-WebRequest downloading payload from "
                f"http://{C2_IP}:8080/stage2.ps1; Parent: powershell.exe; "
                f"ProcessId: {PS_PID}; NewProcessId: {PS_PID}; Image: powershell.exe; "
                "Same session shows defense evasion staging (MITRE T1562 telemetry)."
            ),
        }
    ]


def build_volatility_malfind() -> list[dict[str, Any]]:
    """Düz liste — ``_flatten_vol_tree`` ile uyumlu."""
    shellcode_preview = " ".join(f"{b:02x}" for b in [0x90, 0x90, 0xEB, 0xFE, 0xCC] * 8)
    return [
        {
            "PID": PS_PID,
            "Process": "powershell.exe",
            "ProcessId": PS_PID,
            "ImageFileName": "powershell.exe",
            "Offset": "0x1a2b3000",
            "Disassembly": "0x1000 nopsled; possible shellcode entry",
            "Hexdump": shellcode_preview,
            "Protection": "PAGE_EXECUTE_READWRITE",
        }
    ]


def build_volatility_pslist() -> list[dict[str, Any]]:
    return [
        {
            "PID": PS_PID,
            "PPID": 4120,
            "ImageFileName": "powershell.exe",
            "Process": "powershell.exe",
            "CreateTime": _iso_compact(ANCHOR.replace(minute=17, second=0)),
        }
    ]


def build_volatility_netscan() -> list[dict[str, Any]]:
    """C2’ye çıkan bağlantı + malfind PID — ``run_triple_correlation`` için."""
    return [
        {
            "PID": PS_PID,
            "Process": "powershell.exe",
            "LocalAddress": "192.168.1.50",
            "RemoteAddress": C2_IP,
            "LocalPort": 49152,
            "RemotePort": 4444,
            "State": "ESTABLISHED",
            "CreateTime": _iso_compact(ANCHOR.replace(minute=19, second=5)),
        }
    ]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> int:
    p = argparse.ArgumentParser(description="Sentetik DFIR vaka dosyaları üret")
    p.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "data" / "results",
        help="Çıktı kökü (varsayılan: data/results)",
    )
    p.add_argument(
        "--only",
        nargs="*",
        choices=("mobile", "network", "cloud", "disk", "ram", "all"),
        default=["all"],
        help="Yalnızca seçilen artefaktları yaz",
    )
    args = p.parse_args()
    out: Path = args.out_dir.resolve()
    only = set(args.only)
    if "all" in only:
        only = {"mobile", "network", "cloud", "disk", "ram"}

    written: list[str] = []

    if "mobile" in only:
        mp = out / "mobile_findings.json"
        write_json(mp, build_mobile_findings())
        written.append(str(mp))

    if "network" in only:
        np = out / "network_analysis.json"
        write_json(np, build_network_analysis())
        written.append(str(np))

    if "cloud" in only:
        cp = out / "cloud_findings.json"
        write_json(cp, build_cloud_findings())
        written.append(str(cp))

    if "disk" in only:
        hp = out / "hayabusa_output.json"
        write_json(hp, build_hayabusa_disk_event())
        written.append(str(hp))

    if "ram" in only:
        vdir = out / "volatility"
        write_json(vdir / "windows_malfind.json", build_volatility_malfind())
        write_json(vdir / "windows_pslist.json", build_volatility_pslist())
        write_json(vdir / "windows_netscan.json", build_volatility_netscan())
        written.append(str(vdir / "windows_malfind.json"))
        written.append(str(vdir / "windows_pslist.json"))
        written.append(str(vdir / "windows_netscan.json"))

    print(f"[+] C2 / senaryo IP: {C2_IP}")
    print(f"[+] Ankraj (UTC): {_iso_z(ANCHOR)}")
    print(f"[+] Exfil orig_bytes: {EXFIL_BYTES:,} (~500 MiB)")
    for w in written:
        print(f"    -> {w}")
    print("[i] Streamlit: streamlit run ui/app.py (bulut / mobil / ag panelleri)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
