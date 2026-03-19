"""
SuperTimeline Parser
Farklı araç çıktılarını ortak SuperTimeline formatına dönüştürür.
"""

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# SuperTimeline standart sütunları (Plaso/log2timeline uyumlu)
SUPERTIMELINE_COLUMNS = [
    "timestamp",
    "timestamp_desc",
    "source",
    "message",
    "parser",
    "display_name",
    "hostname",
    "username",
    "filename",
    "extra",
]


@dataclass
class SuperTimelineEvent:
    """Tek bir timeline olayı."""

    timestamp: str
    timestamp_desc: str = ""
    source: str = ""
    message: str = ""
    parser: str = ""
    display_name: str = ""
    hostname: str = ""
    username: str = ""
    filename: str = ""
    extra: str = ""

    def to_row(self) -> dict:
        """CSV satırına dönüştürür."""
        return {
            "timestamp": self.timestamp,
            "timestamp_desc": self.timestamp_desc,
            "source": self.source,
            "message": self.message,
            "parser": self.parser,
            "display_name": self.display_name,
            "hostname": self.hostname,
            "username": self.username,
            "filename": self.filename,
            "extra": self.extra,
        }


class SuperTimelineParser:
    """Çoklu kaynaktan SuperTimeline oluşturur."""

    def __init__(self):
        self._events: list[SuperTimelineEvent] = []
        self._sources: list[Path] = []

    def add_source(self, path: Path) -> int:
        """
        Kaynak dosya/dizinden olayları yükler.

        Args:
            path: CSV veya JSON dosyası, veya dizin

        Returns:
            Eklenen olay sayısı
        """
        count = 0
        if path.is_file():
            count = self._parse_file(path)
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.suffix in (".csv", ".json"):
                    count += self._parse_file(f)

        self._sources.append(path)
        return count

    def _parse_file(self, path: Path) -> int:
        """Tek dosyayı parse eder."""
        count = 0
        suffix = path.suffix.lower()

        if suffix == ".csv":
            for event in self._parse_csv(path):
                self._events.append(event)
                count += 1
        elif suffix == ".json":
            for event in self._parse_json(path):
                self._events.append(event)
                count += 1

        return count

    def _parse_csv(self, path: Path) -> Iterator[SuperTimelineEvent]:
        """CSV dosyasını SuperTimeline formatına dönüştürür."""
        with open(path, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield self._row_to_event(row, source=str(path))

    def _parse_json(self, path: Path) -> Iterator[SuperTimelineEvent]:
        """JSON dosyasını SuperTimeline formatına dönüştürür."""
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if isinstance(item, dict):
                    yield self._dict_to_event(item, source=str(path))

    def _row_to_event(self, row: dict, source: str = "") -> SuperTimelineEvent:
        """CSV satırını SuperTimelineEvent'e map eder."""
        # Yaygın sütun isimleri -> standart alanlar
        mapping = {
            "timestamp": ["timestamp", "time", "datetime", "date", "TimeCreated"],
            "message": ["message", "msg", "description", "Details"],
            "source": ["source", "Source", "log"],
            "parser": ["parser", "plugin", "Parser"],
        }

        def get_value(d: dict, keys: list[str], default: str = "") -> str:
            for k in keys:
                if k in d and d[k]:
                    return str(d[k])
            return default

        return SuperTimelineEvent(
            timestamp=get_value(row, mapping["timestamp"], ""),
            timestamp_desc=row.get("timestamp_desc", row.get("TimestampDescription", "")),
            source=source or get_value(row, mapping["source"]),
            message=get_value(row, mapping["message"]),
            parser=get_value(row, mapping["parser"]),
            display_name=row.get("display_name", row.get("DisplayName", "")),
            hostname=row.get("hostname", row.get("Hostname", "")),
            username=row.get("username", row.get("Username", "")),
            filename=row.get("filename", row.get("Filename", "")),
            extra=json.dumps({k: v for k, v in row.items() if k not in SUPERTIMELINE_COLUMNS}),
        )

    def _dict_to_event(self, d: dict, source: str = "") -> SuperTimelineEvent:
        """JSON dict'i SuperTimelineEvent'e map eder."""
        return SuperTimelineEvent(
            timestamp=str(d.get("timestamp", d.get("TimeCreated", d.get("time", "")))),
            timestamp_desc=str(d.get("timestamp_desc", d.get("TimestampDescription", ""))),
            source=source or str(d.get("source", "")),
            message=str(d.get("message", d.get("Details", d.get("msg", "")))),
            parser=str(d.get("parser", d.get("plugin", ""))),
            display_name=str(d.get("display_name", d.get("DisplayName", ""))),
            hostname=str(d.get("hostname", d.get("Hostname", ""))),
            username=str(d.get("username", d.get("Username", ""))),
            filename=str(d.get("filename", d.get("Filename", ""))),
            extra=json.dumps({k: v for k, v in d.items() if k not in SUPERTIMELINE_COLUMNS}),
        )

    def merge_to(self, output_path: Path) -> int:
        """
        Tüm olayları tek CSV dosyasına yazar.

        Args:
            output_path: Çıktı dosyası

        Returns:
            Yazılan olay sayısı
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Zaman damgasına göre sırala
        sorted_events = sorted(
            self._events,
            key=lambda e: e.timestamp if e.timestamp else "0",
        )

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=SUPERTIMELINE_COLUMNS)
            writer.writeheader()
            for event in sorted_events:
                writer.writerow(event.to_row())

        return len(sorted_events)

    def get_events(self) -> list[SuperTimelineEvent]:
        """Yüklenen tüm olayları döndürür."""
        return self._events
