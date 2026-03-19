"""
Dijital İz Sürücü - Korelasyon Motoru
Hayabusa + Chainsaw çapraz eşleştirme, High Alert vurgulama.

Velociraptor VQL 'Vurgulama' yeteneğiyle uyumlu mantık.
"""

import re
from typing import Any

# Sigma/Chainsaw'dan gelen yetki yükseltme ve ilgili MITRE tactic anahtar kelimeleri
PRIVILEGE_ESCALATION_KEYWORDS = (
    "privilege escalation",
    "yetki yükseltme",
    "privilege_escalation",
    "privesc",
    "T1068",  # MITRE
    "T1055",  # Process Injection
)

# Genişletilebilir: diğer yüksek öncelikli tactic'ler
HIGH_ALERT_KEYWORDS = PRIVILEGE_ESCALATION_KEYWORDS + (
    "lateral movement",
    "credential access",
    "persistence",
)


def _contains_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    """Metinde anahtar kelime var mı (case-insensitive)."""
    if not text:
        return False
    t = text.lower()
    return any(kw.lower() in t for kw in keywords)


def _is_critical_level(level: str) -> bool:
    """Hayabusa Kritik/Yüksek seviyesi mi."""
    l = (level or "").lower().strip()
    return l in ("critical", "crit", "high", "yüksek")


def run_correlation(events: list[dict]) -> list[dict]:
    """
    Korelasyon Motoru: Olayları analiz edip high_alert işaretler.

    Kural: Hem Chainsaw Sigma'da 'Privilege Escalation' (veya ilgili) görünüyorsa,
    hem de Hayabusa 'Kritik' işaretlemişse -> HIGH ALERT (kalın + kırmızı).

    Zaman damgası yakınlığı ile çapraz kaynak eşleştirme de yapılır.

    Args:
        events: Normalize edilmiş timeline (Timestamp, Level, RuleTitle, Details)

    Returns:
        Her olaya 'high_alert': bool eklenmiş liste
    """
    if not events:
        return []

    # 1. Kritik seviyeli zaman damgaları (Hayabusa)
    critical_timestamps: set[str] = set()
    for e in events:
        if _is_critical_level(e.get("Level", "")):
            ts = (e.get("Timestamp", "") or "")[:16]  # YYYY-MM-DD HH:MM
            if ts:
                critical_timestamps.add(ts)

    # 2. Privilege Escalation içeren zaman damgaları (Chainsaw)
    privesc_timestamps: set[str] = set()
    for e in events:
        rt = e.get("RuleTitle", "") or ""
        dt = e.get("Details", "") or ""
        if _contains_keyword(rt + " " + dt, PRIVILEGE_ESCALATION_KEYWORDS):
            ts = (e.get("Timestamp", "") or "")[:16]
            if ts:
                privesc_timestamps.add(ts)

    # 3. High Alert: tek olayda hem kritik hem privesc VEYA zaman damgası çapraz eşleşmesi
    out = []
    for e in events:
        ev = dict(e)
        ts = (ev.get("Timestamp", "") or "")[:16]
        level = ev.get("Level", "")
        rt = ev.get("RuleTitle", "") or ""
        dt = ev.get("Details", "") or ""
        combined = rt + " " + dt

        is_critical = _is_critical_level(level)
        has_privesc = _contains_keyword(combined, PRIVILEGE_ESCALATION_KEYWORDS)

        # Tek olayda her ikisi
        single_match = is_critical and has_privesc

        # Zaman damgası çapraz: Bu olay kritik zamanında VE başka yerde privesc var (veya tersi)
        cross_match = (ts in critical_timestamps and ts in privesc_timestamps) or (
            is_critical and ts in privesc_timestamps
        ) or (has_privesc and ts in critical_timestamps)

        ev["high_alert"] = single_match or cross_match
        out.append(ev)

    return out
