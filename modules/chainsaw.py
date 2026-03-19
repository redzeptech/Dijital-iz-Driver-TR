"""
Chainsaw Modülü - Engine entegrasyonu
BaseModule uyumlu wrapper.
"""

from pathlib import Path
from typing import Any

from core.module_manager import BaseModule

from .chainsaw_wrapper import ChainsawModule as ChainsawScanner


class ChainsawModule(BaseModule):
    """Chainsaw (Sigma rules ile EVTX analizi) - Engine modülü."""

    name = "chainsaw"
    description = "Sigma kurallari ile EVTX analizi (Chainsaw)"
    required_tools = ["chainsaw", "chainsaw.exe"]

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        **kwargs: Any,
    ) -> dict:
        """
        Chainsaw hunt ile EVTX taraması yapar.
        Çıktı: data/results/chainsaw/chainsaw_output.json
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "chainsaw_output.json"

        scanner = ChainsawScanner(
            rules_path=kwargs.get("rules_path", "rules/sigma"),
            mapping_path=kwargs.get("mapping_path"),
        )

        clean_list = scanner.run_hunt(
            evtx_folder=evidence_path,
            output_path=output_file,
            timeout=kwargs.get("timeout", 3600),
        )

        if not output_file.exists():
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": "Chainsaw taramasi basarisiz",
            }

        return {
            "success": True,
            "output_path": str(output_file),
            "events_count": len(clean_list),
        }
