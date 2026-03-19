"""
HayabusaModule - EVTX tarama ve kritik uyarı filtreleme
Sınıf tabanlı Hayabusa wrapper.
"""

import csv
import json
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


class HayabusaModule:
    def __init__(self, executable_path: str | None = None, rules_path: str = "rules"):
        self.executable_path = executable_path or shutil.which("hayabusa") or shutil.which("hayabusa.exe") or "hayabusa"
        self.rules_path = rules_path

    def scan_directory(
        self,
        input_path: str | Path,
        output_name: str | None = None,
        output_format: str = "json",
        timeout: int = 3600,
    ) -> str | None:
        """
        EVTX dosyalarını tarar ve sonuçları data/results/ klasörüne kaydeder.

        Args:
            input_path: .evtx dosyalarının bulunduğu klasör veya tek dosya
            output_name: Çıktı dosya adı (None ise otomatik timestamp)
            output_format: "json" veya "csv"
            timeout: Subprocess timeout (saniye)

        Returns:
            Çıktı dosyasının tam yolu veya hata durumunda None
        """
        if not output_name:
            ext = "json" if output_format == "json" else "csv"
            output_name = f"hayabusa_res_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

        output_dir = Path("data/results")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / output_name

        input_path = Path(input_path)
        if not input_path.exists():
            print(f"[!] Yol bulunamadi: {input_path}")
            return None

        # Tek dosya mi dizin mi?
        if input_path.is_file():
            input_arg, input_val = "-f", str(input_path)
        else:
            input_arg, input_val = "-d", str(input_path)

        subcommand = "json-timeline" if output_format == "json" else "csv-timeline"
        command = [
            self.executable_path,
            subcommand,
            input_arg,
            input_val,
            "-o",
            str(output_path),
            "-p", "standard",
            "--no-wizard",
        ]

        try:
            print(f"[*] Hayabusa taramasi basliyor: {input_path}")
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            print(f"[+] Tarama tamamlandi. Sonuc: {output_path}")
            return str(output_path)
        except subprocess.TimeoutExpired:
            print(f"[!] Hayabusa timeout ({timeout}s)")
            return None
        except subprocess.CalledProcessError as e:
            print(f"[!] Hayabusa hata (kod {e.returncode}): {e.stderr[:300] if e.stderr else e}")
            return None
        except FileNotFoundError:
            print(f"[!] Hayabusa bulunamadi: {self.executable_path}")
            return None
        except Exception as e:
            print(f"[!] Hayabusa calistirilirken hata: {e}")
            return None

    def get_critical_alerts(
        self,
        result_file: str | Path,
    ) -> list[dict[str, Any]]:
        """
        Kritik ve Yuksek seviyeli bulgulari filtreler.

        CSV veya JSON (JSONL) dosyasini okur, Level/Severity alanina gore
        High ve Critical olaylari dondurur.

        Args:
            result_file: Hayabusa ciktisi (csv veya json)

        Returns:
            Filtrelenmis olay listesi
        """
        path = Path(result_file)
        if not path.exists():
            print(f"[!] Dosya bulunamadi: {result_file}")
            return []

        suffix = path.suffix.lower()
        events: list[dict[str, Any]] = []

        try:
            if suffix == ".json":
                events = self._parse_json_result(path)
            else:
                events = self._parse_csv_result(path)
        except Exception as e:
            print(f"[!] Sonuc okunamadi: {e}")
            return []

        level_keys = ("Level", "level", "Severity", "severity")
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

        return filtered

    def hizli_rapor(
        self,
        result_file: str | Path,
        top_ip: int = 10,
        top_rule: int = 10,
    ) -> dict[str, Any]:
        """
        Hayabusa ciktisini analiz edip Hizli Rapor olusturur.
        En cok saldiri girisimi yapan IP adresleri ve en sik tetiklenen kural isimlerini ozetler.

        Args:
            result_file: Hayabusa ciktisi (csv veya json)
            top_ip: En ustte gosterilecek IP sayisi
            top_rule: En ustte gosterilecek kural sayisi

        Returns:
            Dict: top_ips, top_rules, total_events, summary
        """
        path = Path(result_file)
        if not path.exists():
            print(f"[!] Dosya bulunamadi: {result_file}")
            return {"top_ips": [], "top_rules": [], "total_events": 0, "summary": ""}

        suffix = path.suffix.lower()
        try:
            events = self._parse_json_result(path) if suffix == ".json" else self._parse_csv_result(path)
        except Exception as e:
            print(f"[!] Sonuc okunamadi: {e}")
            return {"top_ips": [], "top_rules": [], "total_events": 0, "summary": str(e)}

        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        rule_keys = ("RuleTitle", "rule_title", "Title", "title")

        ip_counter: Counter[str] = Counter()
        rule_counter: Counter[str] = Counter()

        for event in events:
            if not isinstance(event, dict):
                continue

            # RuleTitle say
            for key in rule_keys:
                if key in event and event[key]:
                    rule_counter[str(event[key]).strip()] += 1
                    break

            # IP adreslerini topla (tum alanlardan regex ile)
            ips_found: set[str] = set()
            for val in event.values():
                if not val:
                    continue
                for m in ip_pattern.finditer(str(val)):
                    ips_found.add(m.group())

            for ip in ips_found:
                ip_counter[ip] += 1

        top_ips = [(ip, cnt) for ip, cnt in ip_counter.most_common(top_ip)]
        top_rules = [(rule, cnt) for rule, cnt in rule_counter.most_common(top_rule)]

        summary_lines = [
            f"=== HIZLI RAPOR ===",
            f"Toplam olay: {len(events)}",
            f"",
            f"En cok saldiri girisimi yapan IP'ler (Top {top_ip}):",
        ]
        for ip, cnt in top_ips:
            summary_lines.append(f"  {ip}: {cnt} olay")
        summary_lines.extend(["", f"En sik tetiklenen kurallar (Top {top_rule}):"])
        for rule, cnt in top_rules:
            summary_lines.append(f"  - {rule}: {cnt} kez")

        return {
            "top_ips": top_ips,
            "top_rules": top_rules,
            "total_events": len(events),
            "summary": "\n".join(summary_lines),
        }

    def _parse_csv_result(self, path: Path) -> list[dict]:
        """CSV sonucunu parse eder."""
        events = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(dict(row))
        return events

    def _parse_json_result(self, path: Path) -> list[dict]:
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
