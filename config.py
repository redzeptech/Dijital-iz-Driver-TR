"""
Dijital İz Sürücü - Merkezi Yapılandırma
DFIR araçları, dizin yolları ve ortam kontrolü.
"""

import os
import shutil
from pathlib import Path

# Projenin kök dizini
BASE_DIR = Path(__file__).resolve().parent


def _resolve_tool(name: str, exe: str) -> str:
    """PATH veya proje kokunde binary ara."""
    w = shutil.which(name) or shutil.which(exe)
    if w:
        return w
    for p in [BASE_DIR / exe, BASE_DIR / name]:
        if p.exists():
            return str(p)
    return name


# Araç binary yolları
TOOLS = {
    "hayabusa": _resolve_tool("hayabusa", "hayabusa.exe"),
    "chainsaw": _resolve_tool("chainsaw", "chainsaw.exe"),
    "volatility": _resolve_tool("vol", "volatility.exe"),
    "zeek": _resolve_tool("zeek", "zeek"),
    "tshark": _resolve_tool("tshark", "tshark.exe"),
}

# Dizin yolları
PATHS = {
    "rules_sigma": BASE_DIR / "rules" / "sigma",
    "mappings": BASE_DIR / "mappings",
    "data_results": BASE_DIR / "data" / "results",
}

# Geriye dönük uyumluluk
ROOT = BASE_DIR
CHAINSAW_PATH = TOOLS["chainsaw"]
HAYABUSA_PATH = TOOLS["hayabusa"]
SIGMA_RULES_PATH = PATHS["rules_sigma"]
MAPPING_PATH = PATHS["mappings"] / "sigma-event-logs-all.yml"


def _binary_exists(path: str) -> bool:
    """Binary dosyasının mevcut olup olmadığını kontrol eder."""
    p = Path(path)
    if p.is_absolute():
        return p.exists()
    return bool(shutil.which(path))


def check_env(require_binaries: bool = True) -> bool:
    """
    Gerekli klasörleri oluşturur ve binary dosyalarının varlığını kontrol eder.
    Klasörler (rules, data, results) yoksa os.makedirs ile oluşturulur.

    Args:
        require_binaries: False ise (örn. ``--case-study`` önceden üretilmiş JSON ile)
            Hayabusa/Chainsaw zorunlu olmaz; sadece dizinler hazırlanır.

    Returns:
        Tüm kontroller başarılıysa True, aksi halde False
    """
    # Gerekli klasörleri oluştur
    required_dirs = [
        BASE_DIR / "rules",
        BASE_DIR / "data",
        BASE_DIR / "data" / "results",
        BASE_DIR / "data" / "results" / "volatility",
        BASE_DIR / "data" / "results" / "network",
        PATHS["rules_sigma"],
        PATHS["mappings"],
    ]

    for dir_path in required_dirs:
        if not dir_path.exists():
            os.makedirs(dir_path, exist_ok=True)
            print(f"[+] Klasor olusturuldu: {dir_path}")

    if not require_binaries:
        return True

    # Binary dosyalarını kontrol et
    all_ok = True

    if not _binary_exists(TOOLS["hayabusa"]):
        all_ok = False
    if not _binary_exists(TOOLS["chainsaw"]):
        all_ok = False

    if not all_ok:
        print("\n" + "=" * 60)
        print("Lutfen binary dosyalarini yerlestirin.")
        print("Hayabusa ve Chainsaw binary'lerini proje kok dizinine")
        print("veya sistem PATH'ine ekleyin.")
        print("=" * 60)
        print(f"\nProje kok dizini: {BASE_DIR}")

    return all_ok


# Geriye dönük uyumluluk
check_requirements = check_env
