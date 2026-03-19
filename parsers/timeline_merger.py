"""
TimelineMerger - Çoklu kaynak SuperTimeline birleştirici
Hayabusa CSV, Plaso JSONL ve Zeek loglarını normalize edip tek ana zaman çizelgesi oluşturur.
"""

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

# Normalize edilmiş SuperTimeline sütunları
MERGER_COLUMNS = [
    "Timestamp",
    "Source_Tool",
    "Event_Type",
    "Description",
    "Severity",
]

# Severity sıralaması (yüksekten düşüğe)
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "": 0}


@dataclass
class NormalizedEvent:
    """Normalize edilmiş timeline olayı."""

    timestamp: str
    source_tool: str
    event_type: str
    description: str
    severity: str

    def to_row(self) -> dict:
        return {
            "Timestamp": self.timestamp,
            "Source_Tool": self.source_tool,
            "Event_Type": self.event_type,
            "Description": self.description,
            "Severity": self.severity,
        }


class TimelineMerger:
    """
    Farklı araçlardan gelen verileri normalize eden sınıf.
    Tüm olayları Timestamp, Source_Tool, Event_Type, Description, Severity
    sütunlarına indirgeyip tek bir ana zaman çizelgesi (SuperTimeline) oluşturur.
    """

    def __init__(self):
        self._events: list[NormalizedEvent] = []

    def add_source(self, path: Path, source_tool: str | None = None) -> int:
        """
        Kaynak dosya veya dizinden olayları yükler.
        Kaynak türü dosya uzantısı ve içerikten otomatik tespit edilir.

        Args:
            path: Dosya veya dizin yolu
            source_tool: Zorla belirtmek isterseniz (Hayabusa, Plaso, Zeek)

        Returns:
            Eklenen olay sayısı
        """
        count = 0
        if path.is_file():
            count = self._parse_file(path, source_tool)
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    count += self._parse_file(f, source_tool)
        return count

    def _detect_source_tool(self, path: Path, first_line: str = "") -> str:
        """Dosya türünden kaynak aracı tespit eder."""
        name_lower = path.name.lower()
        if ".jsonl" in name_lower or path.suffix == ".jsonl":
            return "Plaso"
        if "conn.log" in name_lower or "dns.log" in name_lower or "http.log" in name_lower:
            return "Zeek"
        if "hayabusa" in name_lower or (path.suffix == ".csv" and first_line):
            # Hayabusa CSV genelde Timestamp, Level, RuleTitle vb. içerir
            if "Level" in first_line or "RuleTitle" in first_line or "EventID" in first_line:
                return "Hayabusa"
        if path.suffix == ".csv":
            return "Hayabusa"  # Varsayılan CSV -> Hayabusa benzeri
        return "Unknown"

    def _parse_file(self, path: Path, source_tool: str | None = None) -> int:
        """Tek dosyayı parse eder."""
        suffix = path.suffix.lower()
        count = 0

        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                f.seek(0)

                tool = source_tool or self._detect_source_tool(path, first_line)

                if tool == "Plaso" or suffix == ".jsonl":
                    for event in self._parse_plaso_jsonl(f, tool):
                        self._events.append(event)
                        count += 1
                elif tool == "Zeek" or "conn.log" in path.name or "dns.log" in path.name or "http.log" in path.name:
                    for event in self._parse_zeek_tsv(f, path.name, tool):
                        self._events.append(event)
                        count += 1
                else:
                    # Hayabusa CSV veya genel CSV
                    for event in self._parse_hayabusa_csv(f, tool):
                        self._events.append(event)
                        count += 1
        except Exception:
            pass  # Hatalı dosyaları atla

        return count

    def _parse_hayabusa_csv(self, file_handle, source_tool: str) -> Iterator[NormalizedEvent]:
        """Hayabusa CSV formatını parse eder."""
        reader = csv.DictReader(file_handle)
        for row in reader:
            timestamp = self._extract_timestamp(
                row.get("Timestamp") or row.get("timestamp") or row.get("TimeCreated") or ""
            )
            level = row.get("Level") or row.get("level") or row.get("Severity") or "informational"
            rule_title = row.get("RuleTitle") or row.get("Rule Title") or row.get("Title") or ""
            details = row.get("Details") or row.get("details") or row.get("Description") or ""
            description = f"{rule_title}: {details}".strip(": ") if rule_title else details or "Event"

            severity = self._normalize_severity(level)
            event_type = row.get("Channel") or row.get("EventID") or "Event"

            yield NormalizedEvent(
                timestamp=timestamp,
                source_tool=source_tool,
                event_type=str(event_type),
                description=self._sanitize_description(description) if description else "N/A",
                severity=severity,
            )

    def _parse_plaso_jsonl(self, file_handle, source_tool: str) -> Iterator[NormalizedEvent]:
        """Plaso JSONL formatını parse eder (her satır bir JSON nesnesi)."""
        for line in file_handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp = self._extract_timestamp(
                str(obj.get("datetime") or obj.get("timestamp") or obj.get("timestamp_desc") or "")
            )
            message = obj.get("message") or obj.get("description") or ""
            parser = obj.get("parser") or obj.get("sourcetype") or obj.get("plugin") or "Event"
            tag = obj.get("tag") or ""
            if isinstance(tag, list):
                tag = ",".join(str(t) for t in tag)
            description = message or str(obj.get("display_name", "")) or "Plaso event"

            severity = "informational"
            if "critical" in str(tag).lower() or "critical" in str(message).lower():
                severity = "critical"
            elif "high" in str(tag).lower() or "suspicious" in str(message).lower():
                severity = "high"
            elif "medium" in str(tag).lower():
                severity = "medium"

            yield NormalizedEvent(
                timestamp=timestamp,
                source_tool=source_tool,
                event_type=str(parser),
                description=self._sanitize_description(description) if description else "N/A",
                severity=severity,
            )

    def _parse_zeek_tsv(self, file_handle, filename: str, source_tool: str) -> Iterator[NormalizedEvent]:
        """Zeek TSV log formatını parse eder (conn, dns, http vb.)."""
        lines = file_handle.readlines()
        fields = []
        separator = "\t"

        for line in lines:
            line = line.rstrip("\n\r")
            if line.startswith("#separator"):
                separator = "\t"
            elif line.startswith("#fields"):
                parts = line.split("\t")
                fields = parts[1:] if len(parts) > 1 else []
                break

        log_type = "conn"
        if "dns" in filename.lower():
            log_type = "dns"
        elif "http" in filename.lower():
            log_type = "http"
        elif "files" in filename.lower():
            log_type = "files"

        if not fields:
            return

        for line in lines:
            if line.startswith("#"):
                continue
            parts = line.split(separator)
            if len(parts) < len(fields):
                continue

            row = dict(zip(fields, parts))

            ts = row.get("ts", "")
            if ts:
                try:
                    ts_float = float(ts)
                    timestamp = datetime.utcfromtimestamp(ts_float).strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OSError):
                    timestamp = ts
            else:
                timestamp = ""

            description = self._zeek_row_to_description(row, log_type)
            event_type = f"Zeek_{log_type}"

            yield NormalizedEvent(
                timestamp=timestamp,
                source_tool=source_tool,
                event_type=event_type,
                description=self._sanitize_description(description) if description else "N/A",
                severity="informational",
            )

    def _sanitize_description(self, desc: str, max_len: int = 500) -> str:
        """Açıklamayı CSV için temizler."""
        desc = str(desc).replace("\n", " ").replace("\r", " ").strip()
        return desc[:max_len] if len(desc) > max_len else desc

    def _zeek_row_to_description(self, row: dict, log_type: str) -> str:
        """Zeek satırından açıklama üretir."""
        if log_type == "conn":
            orig = row.get("id.orig_h", "") or row.get("id_orig_h", "")
            resp = row.get("id.resp_h", "") or row.get("id_resp_h", "")
            orig_p = row.get("id.orig_p", "") or row.get("id_orig_p", "")
            resp_p = row.get("id.resp_p", "") or row.get("id_resp_p", "")
            proto = row.get("proto", "")
            return self._sanitize_description(f"Connection {orig}:{orig_p} -> {resp}:{resp_p} ({proto})")
        if log_type == "dns":
            query = row.get("query", "")
            answers = row.get("answers", "")
            return self._sanitize_description(f"DNS query: {query}" + (f" -> {answers}" if answers else ""))
        if log_type == "http":
            host = row.get("host", "")
            uri = row.get("uri", "")
            method = row.get("method", "")
            return self._sanitize_description(f"HTTP {method} {host}{uri}")
        return self._sanitize_description(json.dumps({k: v for k, v in row.items() if v and v != "-"}), 300)

    def _extract_timestamp(self, value: str) -> str:
        """Çeşitli timestamp formatlarını normalize eder."""
        value = str(value).strip()
        if not value:
            return ""
        # ISO 8601 (2024-01-15T10:10:00) -> boşlukla
        if "T" in value:
            return value[:19].replace("T", " ")
        if len(value) >= 19:
            return value[:19]
        return value

    def _normalize_severity(self, level: str) -> str:
        """Severity değerini normalize eder."""
        level = str(level).lower().strip()
        mapping = {
            "crit": "critical",
            "critical": "critical",
            "high": "high",
            "med": "medium",
            "medium": "medium",
            "low": "low",
            "info": "informational",
            "informational": "informational",
        }
        return mapping.get(level, "informational")

    def merge_to(self, output_path: Path) -> int:
        """
        Tüm olayları tek SuperTimeline CSV dosyasına yazar.
        Timestamp'e göre sıralanır.

        Args:
            output_path: Çıktı dosyası

        Returns:
            Yazılan olay sayısı
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        sorted_events = sorted(
            self._events,
            key=lambda e: (
                e.timestamp or "0",
                SEVERITY_ORDER.get(e.severity.lower(), 0),
            ),
        )

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=MERGER_COLUMNS)
            writer.writeheader()
            for event in sorted_events:
                writer.writerow(event.to_row())

        return len(sorted_events)

    def get_events(self) -> list[NormalizedEvent]:
        """Yüklenen tüm normalize edilmiş olayları döndürür."""
        return self._events

    def clear(self) -> None:
        """Tüm olayları temizler."""
        self._events.clear()
