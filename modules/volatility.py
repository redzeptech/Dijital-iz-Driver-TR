"""
Volatility3 Wrapper
Bellek imajlarından analiz yapan modül.
.raw, .mem, .dmp, .vmem dosyalarını alıp subprocess ile Volatility3'ü çalıştırır.
"""

import logging
import subprocess
import shutil
from pathlib import Path
from typing import Any

from core.module_manager import BaseModule

logger = logging.getLogger(__name__)

# Bellek imajı uzantıları
MEMORY_EXTENSIONS = {".raw", ".mem", ".dmp", ".vmem", ".img", ".dump"}

# Volatility3: vol (pip) veya volatility
VOL_CMD = shutil.which("vol") or shutil.which("volatility") or "vol"


class VolatilityModule(BaseModule):
    """Volatility3 için wrapper modül."""

    name = "volatility"
    description = "Bellek imaji analizi (Volatility3)"
    required_tools = ["vol", "volatility"]

    def _find_memory_image(self, evidence_path: Path) -> Path | None:
        """Bellek imajı dosyasını bulur."""
        if evidence_path.is_file() and evidence_path.suffix.lower() in MEMORY_EXTENSIONS:
            return evidence_path
        if evidence_path.is_dir():
            for ext in MEMORY_EXTENSIONS:
                matches = list(evidence_path.rglob(f"*{ext}"))
                if matches:
                    return matches[0]
        return None

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        profile: str = "",
        plugins: list[str] | None = None,
        **kwargs: Any,
    ) -> dict:
        """
        Volatility3 ile bellek imajı analizi yapar.

        Bellek imajı dosyasını (.raw, .mem, .dmp vb.) alır, subprocess ile
        Volatility3'ü çalıştırır ve çıktıları output_dir (data/results/) altına kaydeder.

        Args:
            evidence_path: Bellek imajı dosyası veya içeren dizin
            output_dir: Çıktı dizini (data/results/volatility)
            profile: Windows profil (opsiyonel, otomatik tespit denenir)
            plugins: Çalıştırılacak plugin listesi
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        memory_file = self._find_memory_image(evidence_path)
        if not memory_file or not memory_file.exists():
            logger.warning(f"Bellek imaji bulunamadi: {evidence_path}")
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": "Bellek imaji bulunamadi (.raw, .mem, .dmp, .vmem)",
                "evidence_path": str(evidence_path),
            }

        logger.info(f"Bellek imaji: {memory_file}")

        plugins = plugins or [
            "windows.info",
            "windows.pslist",
            "windows.cmdline",
            "windows.netscan",
            "windows.handles",
        ]

        results: dict[str, str] = {}
        for plugin in plugins:
            safe_name = plugin.replace(".", "_")
            output_file = output_dir / f"vol_{safe_name}.json"

            cmd = [
                VOL_CMD,
                "-f",
                str(memory_file),
                "-o",
                str(output_dir),
                plugin,
            ]
            if profile:
                cmd.extend(["-p", profile])

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    encoding="utf-8",
                    errors="replace",
                )
                if proc.returncode == 0:
                    # Volatility3 -o dizine plugin adıyla dosya yazar
                    expected = output_dir / f"{safe_name}.json"
                    results[plugin] = str(expected) if expected.exists() else str(output_dir)
                else:
                    results[plugin] = f"Error: {proc.stderr[:200] if proc.stderr else proc.returncode}"
                    logger.warning(f"Plugin {plugin} basarisiz")
            except subprocess.TimeoutExpired:
                results[plugin] = "Timeout"
                logger.warning(f"Plugin {plugin} timeout")

        success = any("Error" not in v and "Timeout" not in v for v in results.values())

        return {
            "success": success,
            "output_path": str(output_dir),
            "memory_file": str(memory_file),
            "plugin_results": results,
        }
