"""
JSON Parser - Genel JSON işleme yardımcıları
"""

import json
from pathlib import Path
from typing import Any, Iterator


def load_json(path: Path) -> Any:
    """JSON dosyasını yükler."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def iter_json_events(path: Path, event_key: str | None = None) -> Iterator[dict]:
    """
    JSON dosyasından olayları iterate eder.

    Args:
        path: JSON dosyası
        event_key: Olay listesinin bulunduğu anahtar (örn: "events")
    """
    data = load_json(path)
    if event_key and event_key in data:
        items = data[event_key]
    elif isinstance(data, list):
        items = data
    else:
        items = [data]

    for item in items:
        if isinstance(item, dict):
            yield item
