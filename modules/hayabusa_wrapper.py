"""
Hayabusa Wrapper Modülü
Sistemdeki hayabusa.exe (veya binary) ile .evtx dosyalarını tarar.
Çıktıyı JSON formatında data/results/ klasörüne kaydeder.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Hayabusa binary: hayabusa.exe (Windows) veya hayabusa (Linux/Mac)
HAYABUSA_CMD = shutil.which("hayabusa") or shutil.which("hayabusa.exe") or "hayabusa"


def filter_high_critical_events(events: list[dict]) -> list[dict]:
    """
    'High' ve 'Critical' seviyesindeki olayları filtreler.

    Args:
        events: Hayabusa çıktısından gelen olay listesi (dict)

    Returns:
        Sadece High ve Critical seviyeli olaylar
    """
    if not events:
        return []

    filtered = []
    level_keys = ("Level", "level", "Severity", "severity")

    for event in events:
        if not isinstance(event, dict):
            continue
        level = ""
        for key in level_keys:
            if key in event and event[key]:
                level = str(event[key]).lower().strip()
                break

        if level in ("high", "critical", "crit"):
            filtered.append(event)

    return filtered


def scan_evtx_folder(
    evtx_folder: str | Path,
    output_dir: str | Path | None = None,
    timeout: int = 3600,
) -> dict[str, Any]:
    """
    Belirtilen klasördeki .evtx dosyalarını Hayabusa ile tarar.
    Çıktıyı JSON formatında data/results/ klasörüne kaydeder.

    Args:
        evtx_folder: .evtx dosyalarının bulunduğu klasör
        output_dir: Çıktı dizini (varsayılan: data/results/hayabusa_wrapper)
        timeout: Subprocess timeout (saniye)

    Returns:
        Sonuç dict: success, output_path, events, filtered_events, error vb.
    """
    evtx_path = Path(evtx_folder)
    results_dir = Path("data/results")
    output_path = Path(output_dir) if output_dir else results_dir / "hayabusa_wrapper"
    output_path.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "success": False,
        "output_path": "",
        "json_path": "",
        "events": [],
        "filtered_high_critical": [],
        "evtx_count": 0,
        "error": None,
    }

    # .evtx dosyalarını topla
    if evtx_path.is_file() and evtx_path.suffix.lower() == ".evtx":
        evtx_files = [evtx_path]
        scan_target = str(evtx_path.parent) if evtx_path.parent.exists() else str(evtx_path)
        input_arg, input_val = "-f", str(evtx_path)
    elif evtx_path.is_dir():
        evtx_files = list(evtx_path.rglob("*.evtx"))
        input_arg, input_val = "-d", str(evtx_path)
    else:
        result["error"] = f"Gecersiz evtx yolu: {evtx_folder}"
        return result

    if not evtx_files:
        result["error"] = f"Evtx dosyasi bulunamadi: {evtx_folder}"
        return result

    result["evtx_count"] = len(evtx_files)
    json_output = output_path / "hayabusa_results.json"

    cmd = [
        HAYABUSA_CMD,
        "json-timeline",
        input_arg,
        input_val,
        "-o",
        str(json_output),
        "--no-wizard",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )

        if proc.returncode != 0 and proc.stderr:
            logger.warning(f"Hayabusa stderr: {proc.stderr[:500]}")

        # JSON çıktıyı oku (Hayabusa json-timeline: JSONL veya tek JSON)
        events = []
        if json_output.exists():
            with open(json_output, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            try:
                # Tek JSON array/object denemesi
                data = json.loads(content)
                events = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                # JSONL: her satır bir JSON
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            result["events"] = events
            result["filtered_high_critical"] = filter_high_critical_events(events)
            result["success"] = True
        else:
            # JSON yoksa stdout'dan parse dene
            if proc.stdout:
                for line in proc.stdout.splitlines():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                result["events"] = events
                result["filtered_high_critical"] = filter_high_critical_events(events)
            result["success"] = proc.returncode == 0
            if not result["success"]:
                result["error"] = proc.stderr[:500] if proc.stderr else "Bilinmeyen hata"

        result["output_path"] = str(output_path)
        result["json_path"] = str(json_output)

    except subprocess.TimeoutExpired:
        result["error"] = f"Hayabusa timeout ({timeout}s)"
        logger.error(result["error"])
    except FileNotFoundError:
        result["error"] = f"Hayabusa bulunamadi: {HAYABUSA_CMD}"
        logger.error(result["error"])
    except PermissionError as e:
        result["error"] = f"Izin hatasi: {e}"
        logger.exception("Hayabusa izin hatasi")
    except Exception as e:
        result["error"] = str(e)
        logger.exception("Hayabusa tarama hatasi")

    return result


def save_filtered_report(
    events: list[dict],
    output_path: str | Path,
) -> None:
    """
    Filtrelenmiş (High/Critical) olayları ayrı bir JSON dosyasına kaydeder.

    Args:
        events: filter_high_critical_events() çıktısı
        output_path: Kayıt yolu
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(events, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Filtre raporu kaydedilemedi: {e}")
        raise


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    folder = sys.argv[1] if len(sys.argv) > 1 else "data/raw"
    r = scan_evtx_folder(folder)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    if r["success"] and r["filtered_high_critical"]:
        save_filtered_report(
            r["filtered_high_critical"],
            Path(r["output_path"]) / "high_critical_only.json",
        )
        print(f"\nHigh/Critical rapor: {r['output_path']}/high_critical_only.json")
