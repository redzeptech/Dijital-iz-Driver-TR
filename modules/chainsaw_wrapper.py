"""
Chainsaw Wrapper Modülü
chainsaw.exe ile Sigma kurallarını EVTX dosyalarına uygular.
Hayabusa modülüyle aynı sınıf yapısında - main.py'de standart çağrı için.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from config import CHAINSAW_PATH, SIGMA_RULES_PATH, MAPPING_PATH
except ImportError:
    _ROOT = Path(__file__).resolve().parent.parent
    CHAINSAW_PATH = "chainsaw"
    SIGMA_RULES_PATH = _ROOT / "rules" / "sigma"
    MAPPING_PATH = _ROOT / "mappings" / "sigma-event-logs-all.yml"


class ChainsawModule:
    def __init__(
        self,
        executable_path: str | None = None,
        rules_path: str | Path | None = None,
        mapping_path: str | Path | None = None,
    ):
        self.executable_path = executable_path or CHAINSAW_PATH
        self.rules_path = Path(rules_path) if rules_path else Path(SIGMA_RULES_PATH)
        _mp = Path(MAPPING_PATH) if MAPPING_PATH else None
        self.mapping_path = Path(mapping_path) if mapping_path else _mp

    def _find_evtx_files(self, input_path: Path) -> list[Path]:
        """Evtx dosyalarını toplar."""
        if input_path.is_file() and input_path.suffix.lower() == ".evtx":
            return [input_path]
        if input_path.is_dir():
            return list(input_path.rglob("*.evtx"))
        return []

    def run_hunt(
        self,
        evtx_folder: str | Path,
        output_path: str | Path | None = None,
        timeout: int = 3600,
    ) -> list[dict[str, Any]]:
        """
        chainsaw hunt <evtx_klasoru> -s <SIGMA_RULES_PATH> --mapping <MAPPING_PATH> --json
        komutunu calistirir. Ciktiyi parse edip Timestamp, EventID, Rule Title alanlarindan
        temiz bir liste dondurur.

        Args:
            evtx_folder: EVTX dosyalarinin bulundugu klasor
            output_path: JSON cikti dosyasi (None ise gecici)
            timeout: Subprocess timeout (saniye)

        Returns:
            [{"Timestamp": ..., "EventID": ..., "Rule Title": ...}, ...]
        """
        evtx_path = Path(evtx_folder)
        if not evtx_path.exists():
            print(f"[!] Yol bulunamadi: {evtx_folder}")
            return []

        evtx_files = self._find_evtx_files(evtx_path)
        if not evtx_files:
            print(f"[!] UYARI: Evtx dosyasi bulunamadi: {evtx_folder}")
            return []

        out_dir = Path("data/results")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = Path(output_path) if output_path else out_dir / "chainsaw_output.json"

        sigma_path = self.rules_path
        mapping_path = self.mapping_path or Path(MAPPING_PATH)
        if not mapping_path.exists():
            print(f"[!] UYARI: Mapping dosyasi bulunamadi: {mapping_path}")

        command = [
            str(self.executable_path),
            "hunt",
            str(evtx_path),
            "-s", str(sigma_path),
            "--mapping", str(mapping_path),
            "--json",
            "-o", str(out_file),
        ]

        try:
            print(f"[*] Chainsaw hunt basliyor: {evtx_path} ({len(evtx_files)} evtx)")
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"[!] Chainsaw timeout ({timeout}s)")
            return []
        except subprocess.CalledProcessError as e:
            print(f"[!] Chainsaw hata: {e.stderr[:300] if e.stderr else e}")
            return []
        except FileNotFoundError:
            print(f"[!] Chainsaw bulunamadi: {self.executable_path}")
            return []
        except Exception as e:
            print(f"[!] Hata: {e}")
            return []

        return self._parse_hunt_output(out_file)

    def _parse_hunt_output(self, json_path: Path) -> list[dict[str, Any]]:
        """Chainsaw JSON ciktisindan Timestamp, EventID, Rule Title alanlarini cikarir."""
        if not json_path.exists():
            return []

        raw = self._parse_result(json_path)
        clean_list = []

        timestamp_keys = ("Timestamp", "timestamp", "time", "TimeCreated", "Event.System.TimeCreated.SystemTime")
        eventid_keys = ("EventID", "event_id", "Event.System.EventID", "EventId")
        rule_keys = ("Rule Title", "RuleTitle", "rule_title", "Title", "detections", "Detection")

        for event in raw:
            if not isinstance(event, dict):
                continue
            row = {}
            for key in timestamp_keys:
                if key in event and event[key]:
                    row["Timestamp"] = str(event[key])
                    break
            else:
                row["Timestamp"] = ""

            for key in eventid_keys:
                if key in event and event[key]:
                    row["EventID"] = str(event[key])
                    break
            else:
                row["EventID"] = ""

            for key in rule_keys:
                if key in event and event[key]:
                    val = event[key]
                    row["Rule Title"] = val if isinstance(val, str) else str(val)
                    break
            else:
                row["Rule Title"] = ""

            clean_list.append(row)

        return clean_list

    def scan_directory(
        self,
        input_path: str | Path,
        output_path: str | Path | None = None,
        filter_level: bool = True,
        timeout: int = 3600,
    ) -> str | None:
        """
        EVTX klasöründe Sigma kurallarını hunt komutu ile çalıştırır.
        Çıktıyı data/results/chainsaw_output.json olarak kaydeder.

        Args:
            input_path: .evtx dosyalarının bulunduğu klasör
            output_path: Çıktı dosyası (varsayılan: data/results/chainsaw_output.json)
            filter_level: True ise sadece Critical/High olayları alır
            timeout: Subprocess timeout (saniye)

        Returns:
            Çıktı dosyasının tam yolu veya hata durumunda None
        """
        input_path = Path(input_path)
        if not input_path.exists():
            print(f"[!] Yol bulunamadi: {input_path}")
            return None

        evtx_files = self._find_evtx_files(input_path)
        if not evtx_files:
            print(f"[!] UYARI: Evtx dosyasi bulunamadi: {input_path}")
            return None

        output_dir = Path("data/results")
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = Path(output_path) if output_path else output_dir / "chainsaw_output.json"

        sigma_path = self.rules_path
        if not sigma_path.exists():
            print(f"[!] UYARI: Sigma kurallari bulunamadi: {sigma_path}")
            print("    Sigma kurallarini indirin: git clone https://github.com/SigmaHQ/sigma")

        # Mapping dosyasi (Chainsaw v2 icin gerekli)
        mapping_args = []
        if self.mapping_path and self.mapping_path.exists():
            mapping_args = ["-m", str(self.mapping_path)]
        else:
            # Chainsaw kurulum dizinindeki mappings denenebilir
            for m in ["mappings/sigma-event-logs-all.yml", "sigma-event-logs-all.yml"]:
                mp = Path(m)
                if mp.exists():
                    mapping_args = ["-m", str(mp)]
                    break

        command = [
            self.executable_path,
            "hunt",
            str(input_path),
            "-s", str(sigma_path),
            "--json",
            "-o", str(out_file),
            *mapping_args,
        ]

        if filter_level:
            command.extend(["--level", "critical", "--level", "high"])

        try:
            print(f"[*] Chainsaw taramasi basliyor: {input_path} ({len(evtx_files)} evtx)")
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            print(f"[+] Tarama tamamlandi. Sonuc: {out_file}")
            return str(out_file)
        except subprocess.TimeoutExpired:
            print(f"[!] Chainsaw timeout ({timeout}s)")
            return None
        except subprocess.CalledProcessError as e:
            print(f"[!] Chainsaw hata (kod {e.returncode}): {e.stderr[:300] if e.stderr else e}")
            return None
        except FileNotFoundError:
            print(f"[!] Chainsaw bulunamadi: {self.executable_path}")
            return None
        except Exception as e:
            print(f"[!] Chainsaw calistirilirken hata: {e}")
            return None

    def get_critical_alerts(self, result_file: str | Path) -> list[dict[str, Any]]:
        """
        Kritik ve Yuksek seviyeli bulgulari filtreler/dondurur.
        Hunt --level ile zaten filtrelenmisse tum sonucu dondurur.
        """
        path = Path(result_file)
        if not path.exists():
            print(f"[!] Dosya bulunamadi: {result_file}")
            return []

        try:
            events = self._parse_result(path)
        except Exception as e:
            print(f"[!] Sonuc okunamadi: {e}")
            return []

        level_keys = ("level", "Level", "severity", "Severity")
        filtered = []

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
            elif not level:
                filtered.append(event)

        return filtered if filtered else events

    def _parse_result(self, path: Path) -> list[dict]:
        """JSON/JSONL sonucunu parse eder."""
        events = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        try:
            data = json.loads(content)
            events = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return events
