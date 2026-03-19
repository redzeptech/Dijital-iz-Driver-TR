"""
Hayabusa Wrapper
Windows Event Log (.evtx) analizi için modül.
Sistemdeki .evtx dosyalarını alıp subprocess ile Hayabusa'yı çalıştırır.
"""

import logging
import subprocess
import shutil
from pathlib import Path
from typing import Any

from core.module_manager import BaseModule

logger = logging.getLogger(__name__)

# Hayabusa: Windows'ta hayabusa.exe, Linux/Mac'te hayabusa
HAYABUSA_CMD = shutil.which("hayabusa") or shutil.which("hayabusa.exe") or "hayabusa"


class HayabusaModule(BaseModule):
    """Hayabusa (Windows Event Log analizi) için wrapper modül."""

    name = "hayabusa"
    description = "Windows Event Log (.evtx) analizi (Hayabusa)"
    required_tools = ["hayabusa"]

    def _collect_evtx_files(self, evidence_path: Path) -> list[Path]:
        """Verilen yoldan .evtx dosyalarını toplar."""
        evtx_files: list[Path] = []
        if evidence_path.is_file() and evidence_path.suffix.lower() == ".evtx":
            evtx_files.append(evidence_path)
        elif evidence_path.is_dir():
            evtx_files = list(evidence_path.rglob("*.evtx"))
        return evtx_files

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        output_format: str = "csv",
        no_wizard: bool = True,
        **kwargs: Any,
    ) -> dict:
        """
        Hayabusa ile Windows Event Log analizi yapar.

        .evtx dosyalarını veya dizinini alır, subprocess ile Hayabusa'yı
        çalıştırır ve çıktıları output_dir (data/results/) altına kaydeder.

        Args:
            evidence_path: .evtx dosyası veya evtx içeren dizin
            output_dir: Çıktı dizini (data/results/hayabusa)
            output_format: csv veya json
            no_wizard: Etkileşimsiz mod (varsayılan True)
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        evtx_files = self._collect_evtx_files(evidence_path)
        if not evtx_files:
            logger.warning(f"Evtx dosyasi bulunamadi: {evidence_path}")
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": "Evtx dosyasi bulunamadi",
                "evidence_path": str(evidence_path),
            }

        logger.info(f"{len(evtx_files)} evtx dosyasi bulundu")

        # Hayabusa subcommand: csv-timeline veya json-timeline
        subcommand = "csv-timeline" if output_format == "csv" else "json-timeline"
        ext = "csv" if output_format == "csv" else "json"
        output_file = output_dir / f"hayabusa_timeline.{ext}"

        # Tek dosya mi dizin mi?
        if len(evtx_files) == 1:
            input_arg = "-f"
            input_val = str(evtx_files[0])
        else:
            input_arg = "-d"
            input_val = str(evidence_path if evidence_path.is_dir() else evtx_files[0].parent)

        cmd = [
            HAYABUSA_CMD,
            subcommand,
            input_arg,
            input_val,
            "-o",
            str(output_file),
        ]
        if no_wizard:
            cmd.append("--no-wizard")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                encoding="utf-8",
                errors="replace",
            )
            success = result.returncode == 0
            if not success and result.stderr:
                logger.warning(f"Hayabusa stderr: {result.stderr[:500]}")
        except subprocess.TimeoutExpired:
            success = False
            output_file = output_dir / "hayabusa_partial"
            logger.error("Hayabusa timeout (3600s)")

        return {
            "success": success,
            "output_path": str(output_file),
            "format": output_format,
            "evtx_count": len(evtx_files),
            "evidence_path": str(evidence_path),
        }
