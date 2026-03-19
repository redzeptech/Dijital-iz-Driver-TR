"""
AI_Analyst Modülü
SuperTimeline verilerini OpenAI API veya yerel LLM (Ollama) ile analiz eder.
Şüpheli aktiviteleri özetler, çapraz kaynak eşleştirme yapar ve saldırı senaryosu raporu üretir.
"""

import csv
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from core.module_manager import BaseModule

logger = logging.getLogger(__name__)

# Backend: openai | ollama
Provider = Literal["openai", "ollama"]


class AIAnalystModule(BaseModule):
    """SuperTimeline analizi için AI destekli modül."""

    name = "ai_analyst"
    description = "AI ile şüpheli aktivite analizi ve saldırı senaryosu raporu"
    required_tools = []  # API/LLM bağımlılığı runtime'da kontrol edilir

    def __init__(self):
        super().__init__()

    def _validate_tools(self) -> bool:
        return True  # Araç zorunluluğu yok

    def _find_timeline_file(self, evidence_path: Path) -> Path | None:
        """SuperTimeline CSV dosyasını bulur."""
        if evidence_path.is_file() and evidence_path.suffix.lower() == ".csv":
            return evidence_path
        if evidence_path.is_dir():
            for name in ["merged_timeline.csv", "master_timeline.csv", "merged_merger_test.csv"]:
                p = evidence_path / name
                if p.exists():
                    return p
            for f in evidence_path.glob("*.csv"):
                return f
        return None

    def _load_timeline(self, path: Path, max_events: int = 500) -> list[dict]:
        """SuperTimeline CSV'yi yükler."""
        events = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_events:
                    break
                events.append({k: v for k, v in row.items() if v})
        return events

    def _normalize_event_for_prompt(self, e: dict) -> dict:
        """Farklı timeline formatlarını (TimelineMerger, SuperTimelineParser) tek forma indirger."""
        return {
            "Timestamp": e.get("Timestamp") or e.get("timestamp", ""),
            "Source_Tool": e.get("Source_Tool") or e.get("source", ""),
            "Event_Type": e.get("Event_Type") or e.get("parser", ""),
            "Severity": e.get("Severity", ""),
            "Description": e.get("Description") or e.get("message", "")[:200],
        }

    def _build_analysis_prompt(self, events: list[dict]) -> str:
        """LLM için analiz promptu oluşturur."""
        normalized = [self._normalize_event_for_prompt(e) for e in events[:200]]
        events_text = "\n".join(
            f"- [{n['Timestamp']}] {n['Source_Tool']} | {n['Event_Type']} | "
            f"Severity: {n['Severity']} | {n['Description']}"
            for n in normalized
        )

        return f"""Sen bir DFIR (Digital Forensics and Incident Response) uzmanısın. Aşağıda farklı araçlardan (Hayabusa, Plaso, Zeek vb.) birleştirilmiş bir olay zaman çizelgesi var.

Görevin:
1. Şüpheli veya saldırı ile ilişkili aktiviteleri tespit et
2. Farklı kaynaklardan gelen olayları eşleştir (örn: Hayabusa'dan "Brute Force" uyarısı + Zeek'ten yoğun trafik = RDP/SSH brute force saldırısı)
3. Olası saldırı senaryosunu kronolojik olarak özetle
4. Önerilen adımlar ve IOC'ler (Indicators of Compromise) listele

Olay Zaman Çizelgesi:
{events_text}

Lütfen aşağıdaki formatta yanıt ver (Türkçe):

## Özet
[Kısa genel değerlendirme]

## Tespit Edilen Şüpheli Aktivite
[Kaynak araç ve olay eşleştirmeleri]

## Olası Saldırı Senaryosu
[Kronolojik saldırı akışı]

## Önerilen Adımlar
[İzlenmesi gereken adımlar]

## IOC'ler ve İpuçları
[IP, domain, hash, kullanıcı adı vb.]
"""

    def _call_openai(self, prompt: str, model: str = "gpt-4o-mini", **kwargs: Any) -> str:
        """OpenAI API ile analiz yapar."""
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai paketi gerekli: pip install openai")

        api_key = os.environ.get("OPENAI_API_KEY") or kwargs.get("api_key")
        if not api_key:
            raise ValueError("OPENAI_API_KEY ortam değişkeni veya api_key parametresi gerekli")

        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "Sen deneyimli bir siber güvenlik analisti ve DFIR uzmanısın.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=4000,
        )
        return response.choices[0].message.content or ""

    def _call_ollama(self, prompt: str, model: str = "llama3.2", **kwargs: Any) -> str:
        """Ollama (yerel LLM) ile analiz yapar."""
        try:
            from ollama import Client
        except ImportError:
            raise ImportError("ollama paketi gerekli: pip install ollama")

        host = kwargs.get("ollama_host") or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        client = Client(host=host)
        response = client.chat(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "Sen deneyimli bir siber güvenlik analisti ve DFIR uzmanısın. Türkçe yanıt ver.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        return response.message.content or ""

    def _call_llm(self, prompt: str, provider: Provider, **kwargs: Any) -> str:
        """Seçilen provider ile LLM çağrısı yapar."""
        if provider == "openai":
            return self._call_openai(prompt, model=kwargs.get("model", "gpt-4o-mini"), **kwargs)
        if provider == "ollama":
            return self._call_ollama(prompt, model=kwargs.get("model", "llama3.2"), **kwargs)
        raise ValueError(f"Desteklenmeyen provider: {provider}")

    def _detect_provider(self) -> Provider:
        """Kullanılabilir provider'ı tespit eder."""
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        try:
            from ollama import Client
            client = Client()
            client.chat(model="llama3.2", messages=[{"role": "user", "content": "ok"}])
            return "ollama"
        except Exception:
            pass
        return "openai"  # Varsayılan, hata verirse kullanıcı düzeltir

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        provider: Provider | None = None,
        model: str | None = None,
        max_events: int = 500,
        **kwargs: Any,
    ) -> dict:
        """
        SuperTimeline'ı AI ile analiz eder ve saldırı senaryosu raporu üretir.

        Args:
            evidence_path: SuperTimeline CSV dosyası veya dizini
            output_dir: Rapor çıktı dizini (data/results/ai_analyst)
            provider: openai veya ollama (None ise otomatik tespit)
            model: Model adı (gpt-4o-mini, llama3.2 vb.)
            max_events: Analiz edilecek maksimum olay sayısı
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        timeline_path = self._find_timeline_file(evidence_path)
        if not timeline_path or not timeline_path.exists():
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": "SuperTimeline CSV bulunamadi",
                "evidence_path": str(evidence_path),
            }

        events = self._load_timeline(timeline_path, max_events=max_events)
        if not events:
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": "Timeline bos veya okunamadi",
            }

        logger.info(f"{len(events)} olay yuklendi, AI analizi basliyor...")

        provider = provider or self._detect_provider()
        model = model or ("gpt-4o-mini" if provider == "openai" else "llama3.2")

        try:
            prompt = self._build_analysis_prompt(events)
            report = self._call_llm(
                prompt,
                provider=provider,
                model=model,
                api_key=kwargs.get("api_key"),
                ollama_host=kwargs.get("ollama_host"),
            )
        except Exception as e:
            logger.exception("AI analiz hatasi")
            return {
                "success": False,
                "output_path": str(output_dir),
                "error": str(e),
                "provider": provider,
            }

        report_path = output_dir / "ai_analysis_report.md"
        report_path.write_text(report, encoding="utf-8")

        json_path = output_dir / "ai_analysis_metadata.json"
        json_path.write_text(
            json.dumps(
                {
                    "timeline_source": str(timeline_path),
                    "events_analyzed": len(events),
                    "provider": provider,
                    "model": model,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return {
            "success": True,
            "output_path": str(report_path),
            "report_path": str(report_path),
            "metadata_path": str(json_path),
            "events_analyzed": len(events),
            "provider": provider,
            "model": model,
        }
