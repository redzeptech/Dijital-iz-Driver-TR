"""
DFIR Engine - Ana koordinasyon motoru
Tüm modüller arası veri akışını ve işlem sırasını yönetir.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from .module_manager import ModuleManager

logger = logging.getLogger(__name__)


class DFIREngine:
    """Dijital İz Sürücü ana motor sınıfı."""

    def __init__(self, data_dir: Optional[Path] = None):
        """
        Args:
            data_dir: Ham kanıtlar ve sonuçlar için kök dizin.
        """
        self.data_dir = data_dir or Path("data")
        self.raw_evidence_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        self.results_dir = self.data_dir / "results"
        self.supertimeline_dir = self.data_dir / "supertimeline"

        self._ensure_directories()
        self.module_manager = ModuleManager()

    def _ensure_directories(self) -> None:
        """Gerekli dizinleri oluşturur."""
        for directory in [
            self.data_dir,
            self.raw_evidence_dir,
            self.processed_dir,
            self.results_dir,
            self.supertimeline_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Dizin hazır: {directory}")

    def run_module(
        self,
        module_name: str,
        evidence_path: Optional[Path] = None,
        **kwargs: Any,
    ) -> dict:
        """
        Belirtilen modülü çalıştırır.

        Args:
            module_name: Çalıştırılacak modül adı (volatility, hayabusa, kape)
            evidence_path: Kanıt dosyası/dizini yolu
            **kwargs: Modüle özel parametreler

        Returns:
            Modül çıktısı ve durum bilgisi
        """
        module = self.module_manager.get_module(module_name)
        if not module:
            raise ValueError(f"Modül bulunamadı: {module_name}")

        evidence = evidence_path or self.raw_evidence_dir
        output_dir = self.results_dir / module_name

        # ai_analyst için varsayılan kanıt = SuperTimeline
        if module_name == "ai_analyst" and evidence_path is None:
            evidence = self.supertimeline_dir

        logger.info(f"Modül çalıştırılıyor: {module_name}")
        result = module.execute(
            evidence_path=Path(evidence),
            output_dir=output_dir,
            **kwargs,
        )

        return {
            "module": module_name,
            "status": "success" if result.get("success") else "failed",
            "output_path": str(result.get("output_path", "")),
            "details": result,
        }

    def run_pipeline(
        self,
        modules: list[str],
        evidence_path: Optional[Path] = None,
        parse_to_supertimeline: bool = True,
    ) -> dict:
        """
        Birden fazla modülü sırayla çalıştırır ve sonuçları birleştirir.

        Args:
            modules: Çalıştırılacak modül listesi
            evidence_path: Kanıt yolu
            parse_to_supertimeline: Sonuçları SuperTimeline'a dönüştür

        Returns:
            Pipeline sonuç özeti
        """
        results = []
        evidence = evidence_path or self.raw_evidence_dir

        for module_name in modules:
            try:
                result = self.run_module(module_name, evidence)
                results.append(result)
            except Exception as e:
                logger.exception(f"Modül hatası: {module_name}")
                results.append(
                    {
                        "module": module_name,
                        "status": "error",
                        "error": str(e),
                    }
                )

        if parse_to_supertimeline and results:
            self._merge_to_supertimeline(results)

        return {
            "pipeline_complete": True,
            "modules_run": len(modules),
            "results": results,
        }

    def _merge_to_supertimeline(self, results: list[dict]) -> None:
        """Modül çıktılarını SuperTimeline formatına birleştirir."""
        from parsers.supertimeline import SuperTimelineParser

        parser = SuperTimelineParser()
        for result in results:
            output_path = result.get("output_path")
            if output_path and Path(output_path).exists():
                parser.add_source(Path(output_path))
        parser.merge_to(self.supertimeline_dir / "merged_timeline.csv")

    def list_available_modules(self) -> list[dict]:
        """Kullanılabilir modülleri listeler."""
        return self.module_manager.list_modules()
