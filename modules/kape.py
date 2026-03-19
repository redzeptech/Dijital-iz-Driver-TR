"""
KAPE Wrapper
KAPE (Kroll Artifact Parser and Extractor) için modül.
"""

import subprocess
from pathlib import Path
from typing import Any

from core.module_manager import BaseModule


class KAPEModule(BaseModule):
    """KAPE için wrapper modül."""

    name = "kape"
    description = "Artefakt toplama ve analiz (KAPE)"
    required_tools = ["kape"]

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        target: str = "!SANS_Triage",
        **kwargs: Any,
    ) -> dict:
        """
        KAPE ile artefakt toplama ve analiz yapar.

        Args:
            evidence_path: Kaynak disk/dizin
            output_dir: Çıktı dizini
            target: KAPE target (örn: !SANS_Triage, !BasicCollection)
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "kape",
            "--tsource",
            str(evidence_path),
            "--tdest",
            str(output_dir),
            "--target",
            target,
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            success = True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            success = False
            output_dir = output_dir / "kape_error"

        return {
            "success": success,
            "output_path": str(output_dir),
            "target": target,
        }
