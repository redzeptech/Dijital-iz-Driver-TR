"""
CSV Parser - Genel CSV işleme yardımcıları
"""

import csv
from pathlib import Path
from typing import Iterator


def read_csv_headers(path: Path) -> list[str]:
    """CSV dosyasının sütun başlıklarını döndürür."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        return next(reader, [])


def iter_csv_rows(path: Path) -> Iterator[dict]:
    """CSV dosyasını satır satır dict olarak iterate eder."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        yield from reader
