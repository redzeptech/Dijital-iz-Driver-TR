"""
Dijital İz Sürücü - Veri Maskeleme Modülü
Kişisel verileri gizleme (Cellebrite / Magnet AXIOM rapor standartları).

E-posta, IP adresi ve kullanıcı adlarını maskeleyerek
HTML/PDF raporlarına basılmadan önce hassas veriyi korur.

Atıf: Cellebrite ve Magnet AXIOM "Kişisel Verileri Gizleme" (Personal Data
Redaction) standartları baz alınmıştır.
"""

import re
from typing import Any, Optional


def _mask_username(name: str) -> str:
    """
    Kullanıcı adını maskele: admin -> a***n
    Kısa isimler (<=2 karakter) tamamen maske.
    """
    name = name.strip()
    if not name or len(name) <= 2:
        return "***"
    if len(name) == 3:
        return name[0] + "*" + name[-1]
    return name[0] + "*" * (len(name) - 2) + name[-1]


def _mask_email_local(local: str) -> str:
    """E-posta local kısmı: user -> u***r"""
    if len(local) <= 2:
        return "*" * len(local)
    return local[0] + "*" * (len(local) - 2) + local[-1]


def _mask_email_domain(domain: str) -> str:
    """E-posta domain: example.com -> e***e.com"""
    if "." not in domain:
        return _mask_username(domain)
    name, tld = domain.rsplit(".", 1)
    if len(name) <= 2:
        masked_name = "*" * len(name)
    else:
        masked_name = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked_name}.{tld}"


def mask_data(
    text: str,
    mask_emails: bool = True,
    mask_ips: bool = True,
    mask_usernames: bool = True,
    ip_replacement: str = "x.x.x.x",
) -> str:
    """
    Metindeki hassas verileri maskele.

    Cellebrite / Magnet AXIOM "Kişisel Verileri Gizleme" standartlarına
    uygun: E-posta, IP adresi (isteğe bağlı), kullanıcı adları.

    Args:
        text: Maskelenecek metin
        mask_emails: E-posta adreslerini maskele
        mask_ips: IP adreslerini maskele (varsayılan: True)
        mask_usernames: Yaygın kullanıcı adı pattern'lerini maskele
        ip_replacement: IP maskelendiğinde kullanılacak metin

    Returns:
        Maskelenmiş metin

    Örnek:
        >>> mask_data("admin@corp.com logged from 192.168.1.100")
        "a***n@c***p.com logged from x.x.x.x"
    """
    if not text or not isinstance(text, str):
        return text

    result = text

    # 1. E-posta adresleri (user@domain.tld)
    if mask_emails:
        email_pattern = re.compile(
            r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)\b"
        )

        def _replace_email(m: re.Match) -> str:
            local, domain = m.group(1), m.group(2)
            return f"{_mask_email_local(local)}@{_mask_email_domain(domain)}"

        result = email_pattern.sub(_replace_email, result)

    # 2. IP adresleri (IPv4)
    if mask_ips:
        ip_pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        result = ip_pattern.sub(ip_replacement, result)

    # 3. Kullanıcı adları (Username:, User:, SubjectUserName vb. sonrası)
    if mask_usernames:
        # Pattern: "Username: admin" veya "User=admin" veya "admin" (tek başına yaygın isimler)
        username_context_pattern = re.compile(
            r"(?:Username|User|SubjectUserName|TargetUserName|AccountName|LogonAccount)"
            r"\s*[:=]\s*([a-zA-Z0-9_.-]{2,})",
            re.IGNORECASE,
        )

        result = username_context_pattern.sub(
            lambda m: m.group(0).replace(m.group(1), _mask_username(m.group(1))),
            result,
        )

        # Yaygın tek kelime kullanıcı adları (domain\user veya user formatında)
        domain_user_pattern = re.compile(
            r"\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.-]{2,})\b"
        )
        result = domain_user_pattern.sub(
            lambda m: f"{_mask_username(m.group(1))}\\{_mask_username(m.group(2))}",
            result,
        )

    return result


def mask_event(event: dict, keys_to_mask: Optional[list[str]] = None) -> dict:
    """
    Olay sözlüğündeki belirli anahtarların değerlerini maskeler.
    HTML/PDF rapor öncesi timeline olayları için.

    Args:
        event: Olay sözlüğü
        keys_to_mask: Maskelenecek anahtarlar (None ise: Details, Description, message)

    Returns:
        Maskelenmiş kopya
    """
    keys = keys_to_mask or ["Details", "Description", "message", "ExtraFieldInfo"]
    out = dict(event)
    for key in keys:
        if key in out and out[key]:
            out[key] = mask_data(str(out[key]))
    return out


def mask_structure(data: Any) -> Any:
    """
    Dict / list içindeki tüm metinleri ``mask_data`` ile maskeleyerek KVKK uyumlu kopya üretir.
    Sayı ve bool aynen kalır (PDF/HTML korelasyon blokları için).
    """
    if data is None:
        return None
    if isinstance(data, str):
        return mask_data(data)
    if isinstance(data, dict):
        return {str(k): mask_structure(v) for k, v in data.items()}
    if isinstance(data, list):
        return [mask_structure(v) for v in data]
    if isinstance(data, (int, float, bool)):
        return data
    return mask_data(str(data))
