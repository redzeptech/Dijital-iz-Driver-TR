"""
Dijital İz Sürücü - Volatility 3 Wrapper
Bellek imajlarından derin analiz: süreçler, ağ, şüpheli enjeksiyonlar.

Volatility 3 (vol.py) kütüphanesi veya binary kullanır.
Rekall ve Redline araçlarının derin bellek analizi mantığını
DİZ'in hızlı mimarisiyle birleştirir.

Atıf: Rekall, Redline - Bellek forensik standartları.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Proje kökü
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Varsayılan pluginler
DEFAULT_PLUGINS = [
    "windows.pslist",   # Süreç listesi
    "windows.netscan",  # Ağ bağlantıları
    "windows.malfind",  # Şüpheli bellek enjeksiyonları
]

# Bellek imajı uzantıları
MEMORY_EXTENSIONS = {".raw", ".mem", ".dmp", ".vmem", ".img", ".dump"}


def _resolve_vol_cmd() -> str:
    """vol, volatility veya vol.py binary'sini bulur."""
    for cmd in ("vol", "volatility", "vol.py"):
        found = shutil.which(cmd)
        if found:
            return found
    # Proje kökünde
    for exe in (_ROOT / "vol.exe", _ROOT / "volatility.exe"):
        if exe.exists():
            return str(exe)
    return "vol"


def _find_memory_image(path: str | Path) -> Path | None:
    """Bellek imajı dosyasını bulur."""
    p = Path(path)
    if p.is_file() and p.suffix.lower() in MEMORY_EXTENSIONS:
        return p
    if p.is_dir():
        for ext in MEMORY_EXTENSIONS:
            matches = list(p.rglob(f"*{ext}"))
            if matches:
                return matches[0]
    return None


def _apply_masking(data: Any, mask: bool) -> Any:
    """
    Süreç/ağ verilerindeki kullanıcı bilgilerini maskeler.
    core/masking.mask_data kullanır (KVKK uyumlu).
    """
    if not mask:
        return data

    try:
        from core.masking import mask_data
    except ImportError:
        return data

    if isinstance(data, str):
        return mask_data(data)
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if isinstance(v, str):
                # Tüm string alanları maskele (süreç yolu, IP, kullanıcı vb.)
                out[k] = mask_data(v)
            else:
                out[k] = _apply_masking(v, mask)
        return out
    if isinstance(data, list):
        return [_apply_masking(item, mask) for item in data]
    return data


class VolatilityWrapper:
    """
    Volatility 3 wrapper - bellek imajı analizi.

    Kullanım:
        vol = VolatilityWrapper()
        results = vol.run_analysis("memory.raw", mask_sensitive=True)
    """

    def __init__(
        self,
        executable_path: str | None = None,
        output_base: str | Path | None = None,
    ):
        self.executable_path = executable_path or _resolve_vol_cmd()
        self.output_base = Path(output_base) if output_base else _ROOT / "data" / "results" / "volatility"

    def run_analysis(
        self,
        memory_path: str | Path,
        plugins: list[str] | None = None,
        mask_sensitive: bool = False,
        timeout: int = 600,
    ) -> dict[str, Any]:
        """
        Bellek imajı üzerinde Volatility 3 pluginlerini çalıştırır.
        Çıktıları JSON formatında data/results/volatility/ altına kaydeder.

        Args:
            memory_path: Bellek imajı dosyası veya içeren klasör
            plugins: Çalıştırılacak pluginler (varsayılan: pslist, netscan, malfind)
            mask_sensitive: Süreç isimlerindeki kullanıcı bilgilerini maskele
            timeout: Plugin başına timeout (saniye)

        Returns:
            {
                "success": bool,
                "memory_file": str,
                "output_dir": str,
                "results": {"windows.pslist": [...], "windows.netscan": [...], ...},
                "errors": {"plugin": "hata mesajı"}
            }
        """
        memory_file = _find_memory_image(memory_path)
        if not memory_file or not memory_file.exists():
            return {
                "success": False,
                "memory_file": "",
                "output_dir": str(self.output_base),
                "results": {},
                "errors": {"memory": f"Bellek imajı bulunamadı: {memory_path}"},
            }

        plugins = plugins or DEFAULT_PLUGINS
        self.output_base.mkdir(parents=True, exist_ok=True)

        results: dict[str, Any] = {}
        errors: dict[str, str] = {}

        for plugin in plugins:
            safe_name = plugin.replace(".", "_")
            output_file = self.output_base / f"{safe_name}.json"

            cmd = [
                self.executable_path,
                "-f", str(memory_file),
                "-r", "json",
                "-q",
                plugin,
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding="utf-8",
                    errors="replace",
                    cwd=str(_ROOT),
                )

                if proc.returncode != 0:
                    err_msg = (proc.stderr or proc.stdout or str(proc.returncode))[:500]
                    errors[plugin] = err_msg
                    print(f"[!] {plugin} hata: {err_msg[:200]}")
                    continue

                # Volatility JSON stdout'a yazar
                raw_output = proc.stdout
                if not raw_output or not raw_output.strip():
                    errors[plugin] = "Boş çıktı"
                    continue

                try:
                    parsed = json.loads(raw_output)
                except json.JSONDecodeError:
                    # Bazen tree yapısı olabilir, düz metin olarak sakla
                    parsed = {"raw": raw_output[:10000]}

                # Masking uygula
                parsed = _apply_masking(parsed, mask_sensitive)

                # JSON dosyasına kaydet
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(parsed, f, ensure_ascii=False, indent=2)

                # Tree yapısından düz listeye çevir (varsa)
                if isinstance(parsed, dict) and "__children" in parsed:
                    results[plugin] = parsed.get("__children", [parsed])
                elif isinstance(parsed, list):
                    results[plugin] = parsed
                else:
                    results[plugin] = parsed

                print(f"[+] {plugin} -> {output_file}")

            except subprocess.TimeoutExpired:
                errors[plugin] = f"Timeout ({timeout}s)"
                print(f"[!] {plugin} timeout")
            except FileNotFoundError:
                errors[plugin] = f"Binary bulunamadı: {self.executable_path}"
                print(f"[!] Volatility bulunamadı: {self.executable_path}")
                break
            except Exception as e:
                errors[plugin] = str(e)[:300]
                print(f"[!] {plugin}: {e}")

        return {
            "success": len(results) > 0,
            "memory_file": str(memory_file),
            "output_dir": str(self.output_base),
            "results": results,
            "errors": errors,
        }

    def run_pslist(
        self,
        memory_path: str | Path,
        mask_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        """Sadece windows.pslist çalıştırır, süreç listesi döner."""
        out = self.run_analysis(
            memory_path,
            plugins=["windows.pslist"],
            mask_sensitive=mask_sensitive,
        )
        data = out.get("results", {}).get("windows.pslist", [])
        if isinstance(data, dict) and "__children" in data:
            return data.get("__children", [])
        return data if isinstance(data, list) else []

    def run_netscan(
        self,
        memory_path: str | Path,
        mask_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        """Sadece windows.netscan çalıştırır."""
        out = self.run_analysis(
            memory_path,
            plugins=["windows.netscan"],
            mask_sensitive=mask_sensitive,
        )
        data = out.get("results", {}).get("windows.netscan", [])
        if isinstance(data, dict) and "__children" in data:
            return data.get("__children", [])
        return data if isinstance(data, list) else []

    def run_malfind(
        self,
        memory_path: str | Path,
        mask_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        """Sadece windows.malfind çalıştırır - şüpheli enjeksiyonlar."""
        out = self.run_analysis(
            memory_path,
            plugins=["windows.malfind"],
            mask_sensitive=mask_sensitive,
        )
        data = out.get("results", {}).get("windows.malfind", [])
        if isinstance(data, dict) and "__children" in data:
            return data.get("__children", [])
        return data if isinstance(data, list) else []
