#!/usr/bin/env python3
"""
Dijital İz Sürücü - Ortam Kurulum Scripti
rules/ klasörünü oluşturur ve Sigma kurallarını indirir.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RULES_DIR = ROOT / "rules"
SIGMA_REPO = "https://github.com/SigmaHQ/sigma"
SIGMA_TARGET = RULES_DIR / "sigma"


def main() -> int:
    print("[*] Dijital Iz Surucu - Ortam Kurulumu\n")

    # rules/ klasörünü oluştur
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[+] rules/ klasoru hazir: {RULES_DIR}")

    # Sigma kurallarını clone et
    if SIGMA_TARGET.exists():
        print(f"[*] Sigma kurallari zaten mevcut: {SIGMA_TARGET}")
        print("    Guncellemek icin: cd rules/sigma && git pull")
    else:
        print(f"[*] Sigma kurallari indiriliyor: {SIGMA_REPO}")
        try:
            subprocess.run(
                ["git", "clone", SIGMA_REPO, str(SIGMA_TARGET)],
                check=True,
                capture_output=True,
                text=True,
            )
            print(f"[+] Sigma kurallari indirildi: {SIGMA_TARGET}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Git clone hatasi: {e.stderr or e}")
            return 1
        except FileNotFoundError:
            print("[!] Git bulunamadi. Git kurulumu gerekli.")
            return 1

    # Kullanıcı uyarısı
    print("\n" + "=" * 60)
    print("Lutfen Chainsaw ve Hayabusa binary dosyalarini projenin")
    print("kok dizinine atin.")
    print("=" * 60)
    print(f"\nProje kok dizini: {ROOT}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
