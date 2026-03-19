#!/usr/bin/env python3
"""
Dijital İz Sürücü - Orkestra Başlatıcı
EVTX analizi: Hayabusa + Chainsaw -> Birleşik Timeline
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _sync_case_study_artifacts(artifacts_dir: Path, results_dir: Path) -> None:
    """``tests/case_study/artifacts`` içeriğini ``data/results`` altına kopyalar."""
    if not artifacts_dir.is_dir():
        print(f"[!] Case study artifacts klasoru yok: {artifacts_dir}")
        return
    for src in artifacts_dir.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(artifacts_dir)
        dest = results_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    print(f"[+] Case study artefaktlari: {artifacts_dir} -> {results_dir}")


def _load_json_events_list(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    return []


def main() -> int:
    """Ana giriş noktası."""
    # 1. Argparse (ortam kontrolü case-study sonrası)
    parser = argparse.ArgumentParser(
        prog="dijital-iz-surucu",
        description="Dijital İz Sürücü - Hayabusa + Chainsaw EVTX Analizi",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=False,
        default=None,
        help="EVTX dosyalarının bulunduğu klasör (--case-study ile varsayilan: <case>/evtx)",
    )
    parser.add_argument(
        "--case-study",
        type=Path,
        default=None,
        metavar="DIR",
        help="Sentetik/entegre vaka kökü (örn. tests/case_study): artifacts/ -> data/results, evtx/ disk taraması",
    )
    parser.add_argument(
        "--report",
        "-r",
        type=Path,
        default=None,
        metavar="PATH",
        help="HTML Storyline raporu yolu; --pdf ile kullanılmazsanız varsayılan: data/results/diz_vaka_raporu_001.html",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="PDF üretir: data/results/diz_vaka_raporu_001.pdf (HTML çıktısı gerekir; -r yoksa HTML aynı dizine yazılır)",
    )
    parser.add_argument(
        "--memory",
        "-m",
        type=Path,
        metavar="PATH",
        help="Bellek imajı (.raw, .dmp vb.) - Disk+Bellek korelasyonu için",
    )
    parser.add_argument(
        "--pcap",
        "-p",
        type=Path,
        metavar="PATH",
        help="PCAP dosyası - Üçlü korelasyon (Ağ+Bellek+Disk) için",
    )
    parser.add_argument(
        "--diz-ai",
        action="store_true",
        help="DİZ-Analist: Hayabusa/Chainsaw/Volatility kritik bulgularından LLM ile saldırı senaryosu (OPENAI veya Ollama)",
    )
    parser.add_argument(
        "--ai-detective",
        action="store_true",
        help="DİZ-Analist: dedektif raporu (baslangic / ilerleyis / sonuc) + correlator zaman hizalaması",
    )
    parser.add_argument(
        "--ai-provider",
        choices=["openai", "ollama"],
        default=None,
        help="LLM sağlayıcı (yoksa OPENAI_API_KEY varsa OpenAI, yoksa Ollama)",
    )
    parser.add_argument(
        "--ai-model",
        default=None,
        metavar="MODEL",
        help="Model adı (örn. gpt-4o-mini, llama3.2)",
    )
    args = parser.parse_args()

    from config import TOOLS, check_env

    case_root = Path(args.case_study).resolve() if args.case_study else None
    if case_root:
        if not check_env(require_binaries=False):
            return 1
    else:
        if not check_env():
            return 1

    results_dir = ROOT / "data" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    if case_root:
        _sync_case_study_artifacts(case_root / "artifacts", results_dir)
        input_path = Path(args.input).resolve() if args.input else (case_root / "evtx")
    else:
        if not args.input:
            print("[!] --input (-i) veya --case-study gerekli.")
            return 1
        input_path = Path(args.input).resolve()

    if not input_path.exists():
        print(f"[!] Yol bulunamadi: {input_path}")
        return 1

    has_evtx = False
    if input_path.is_file():
        has_evtx = input_path.suffix.lower() == ".evtx"
    elif input_path.is_dir():
        has_evtx = any(input_path.glob("**/*.evtx"))

    from core.utils import normalize_events_batch
    from modules.chainsaw_wrapper import ChainsawModule
    from modules.hayabusa_module import HayabusaModule

    hayabusa_events: list[dict] = []
    chainsaw_raw: list[dict] = []

    if case_root and not has_evtx:
        print("\n[*] Case study: EVTX yok; disk kanali JSON artefaktlarindan (artifacts).")
        hayabusa_events = _load_json_events_list(results_dir / "hayabusa_output.json")
        if not hayabusa_events:
            hayabusa_events = _load_json_events_list(results_dir / "hayabusa.json")
        chainsaw_raw = _load_json_events_list(results_dir / "chainsaw_output.json")
    else:
        hayabusa = HayabusaModule(executable_path=TOOLS.get("hayabusa"))
        chainsaw = ChainsawModule(executable_path=TOOLS.get("chainsaw"))
        print("\n[*] Hayabusa taramasi basliyor...")
        hayabusa_output = hayabusa.scan_directory(input_path, output_format="json")
        print("\n[*] Chainsaw taramasi basliyor...")
        chainsaw_raw = chainsaw.run_hunt(input_path)
        if hayabusa_output and Path(hayabusa_output).exists():
            with open(hayabusa_output, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            try:
                data = json.loads(content)
                hayabusa_events = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            hayabusa_events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

    hayabusa_normalized = normalize_events_batch(hayabusa_events, "Hayabusa")
    chainsaw_normalized = normalize_events_batch(chainsaw_raw, "Chainsaw")
    final_timeline = hayabusa_normalized + chainsaw_normalized

    # 5b. Ağ analizi (--pcap ile)
    network_results: dict | None = None
    if getattr(args, "pcap", None) and Path(args.pcap).exists():
        from modules.network_wrapper import NetworkWrapper

        print("\n[*] Ag analizi (Zeek/Tshark) basliyor...")
        nw = NetworkWrapper()
        network_results = nw.run_analysis(args.pcap, extract_files=False, mask_ips=True)
        if network_results.get("success"):
            print(f"[+] Ag analizi: {network_results.get('network_analysis_path', '')}")

    # 5c. Volatility (--memory ile): SuperTimeline + Disk-Bellek korelasyonu
    volatility_results: dict | None = None
    confirmed_threats: list[dict] = []
    exfiltration_threats: list[dict] = []
    account_takeover_threats: list[dict] = []
    full_spectrum_threats: list[dict] = []
    if getattr(args, "memory", None) and Path(args.memory).exists():
        from core.utils import normalize_volatility_netscan_batch, normalize_volatility_pslist_batch
        from core.correlator import run_disk_memory_correlation
        from modules.volatility_wrapper import VolatilityWrapper

        print("\n[*] Bellek analizi (Volatility) basliyor...")
        vol = VolatilityWrapper()
        volatility_results = vol.run_analysis(args.memory, mask_sensitive=True)
        if volatility_results.get("success"):
            results = volatility_results.get("results", {})
            # SuperTimeline: netscan + pslist olaylarını ekle
            netscan = results.get("windows.netscan", results.get("windows.netscan.NetScan", []))
            pslist = results.get("windows.pslist", results.get("windows.pslist.PsList", []))
            if netscan:
                net_events = normalize_volatility_netscan_batch(netscan)
                final_timeline.extend(net_events)
                print(f"[+] SuperTimeline: {len(net_events)} NETWORK_MEMORY olayi eklendi")
            if pslist:
                proc_events = normalize_volatility_pslist_batch(pslist)
                final_timeline.extend(proc_events)
                print(f"[+] SuperTimeline: {len(proc_events)} PROCESS_MEMORY olayi eklendi")
            # Disk + Bellek korelasyonu
            final_timeline, confirmed_threats = run_disk_memory_correlation(
                final_timeline, volatility_results
            )
            if confirmed_threats:
                print(f"[!!!] KESINLESMIS TEHDIT: {len(confirmed_threats)} (Disk + RAM dogrulamali)")
        else:
            print("[!] Volatility sonucu alinamadi.")
    elif case_root:
        from core.correlator import load_volatility_bundle_from_results, run_disk_memory_correlation
        from core.utils import normalize_volatility_netscan_batch, normalize_volatility_pslist_batch

        volatility_results = load_volatility_bundle_from_results(results_dir)
        if volatility_results and volatility_results.get("success"):
            results = volatility_results.get("results", {})
            netscan = results.get("windows.netscan", results.get("windows.netscan.NetScan", []))
            pslist = results.get("windows.pslist", results.get("windows.pslist.PsList", []))
            if netscan:
                net_events = normalize_volatility_netscan_batch(netscan)
                final_timeline.extend(net_events)
                print(f"[+] Case study RAM (JSON): {len(net_events)} NETWORK_MEMORY olayi")
            if pslist:
                proc_events = normalize_volatility_pslist_batch(pslist)
                final_timeline.extend(proc_events)
                print(f"[+] Case study RAM (JSON): {len(proc_events)} PROCESS_MEMORY olayi")
            final_timeline, confirmed_threats = run_disk_memory_correlation(
                final_timeline, volatility_results
            )
            if confirmed_threats:
                print(f"[!!!] KESINLESMIS TEHDIT: {len(confirmed_threats)} (Disk + RAM JSON)")

    # 5d. Üçlü Korelasyon (Ağ + Bellek + Disk) -> Veri Sızıntısı
    from core.correlator import (
        build_cross_source_timestamp_alignment,
        run_cloud_account_takeover_correlation,
        run_full_spectrum_correlation,
        run_triple_correlation,
        _load_network_results_disk,
    )

    final_timeline, exfiltration_threats = run_triple_correlation(
        final_timeline, volatility_results, network_results
    )
    if exfiltration_threats:
        print(f"[!!!] KRITIK VERI SIZINTISI: {len(exfiltration_threats)} (Uclu korelasyon)")

    # 5e. Akıllı Bulut-Yerel Korelasyon (Zeek AWS/Azure API + CloudTrail yetki + PS Cloud Module) -> ATO
    cloud_blob: dict = {}
    cloud_path = ROOT / "data" / "results" / "cloud_findings.json"
    if cloud_path.exists():
        try:
            with open(cloud_path, encoding="utf-8", errors="ignore") as f:
                cloud_blob = json.load(f)
        except json.JSONDecodeError:
            cloud_blob = {}
    final_timeline, account_takeover_threats = run_cloud_account_takeover_correlation(
        final_timeline,
        network_results,
        cloud_blob if cloud_blob else None,
    )
    if account_takeover_threats:
        print(
            f"[!!!] BULUT HESABI ELE GECIRME (ATO): {len(account_takeover_threats)} "
            "(Ag + Bulut + Disk akilli korelasyon)"
        )

    # 5f. DİZ-Tam-Saha-Pres: Mobil + Zeek(LAN) + Bulut(Admin) + Disk(Lateral) -> TOPYEKÜN SİBER SALDIRI
    mobile_blob: dict = {}
    mobile_path = ROOT / "data" / "results" / "mobile_findings.json"
    if mobile_path.exists():
        try:
            with open(mobile_path, encoding="utf-8", errors="ignore") as f:
                mobile_blob = json.load(f)
        except json.JSONDecodeError:
            mobile_blob = {}
    final_timeline, full_spectrum_threats = run_full_spectrum_correlation(
        final_timeline,
        network_results,
        cloud_blob if cloud_blob else None,
        mobile_blob if mobile_blob else None,
    )
    if full_spectrum_threats:
        print(
            f"[!!!] TOPYEKUN SIBER SALDIRI (Tam-Saha-Pres): {len(full_spectrum_threats)} "
            "(Mobil + Ag + Bulut + Disk)"
        )

    nr_align = (
        network_results
        if (network_results and network_results.get("connections"))
        else _load_network_results_disk()
    )
    cross_alignment = build_cross_source_timestamp_alignment(
        final_timeline,
        mobile_blob if mobile_blob else None,
        cloud_blob if cloud_blob else None,
        nr_align if nr_align else None,
        volatility_results,
    )
    try:
        with open(results_dir / "cross_source_alignment.json", "w", encoding="utf-8") as f:
            json.dump(cross_alignment, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
    summ = str(cross_alignment.get("summary_tr") or "").strip()
    if summ:
        print("\n[*] Cok kaynakli zaman hizalama (correlator):")
        print(summ[:1800] + ("..." if len(summ) > 1800 else ""))

    try:
        with open(results_dir / "correlation_results.json", "w", encoding="utf-8") as f:
            json.dump(
                {
                    "confirmed_threats": confirmed_threats,
                    "exfiltration_threats": exfiltration_threats,
                    "account_takeover_threats": account_takeover_threats,
                    "full_spectrum_threats": full_spectrum_threats,
                    "cross_source_alignment": cross_alignment,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except OSError:
        pass

    # 6. Korelasyon Motoru (High Alert: Kritik + Privilege Escalation)
    from core.correlation import run_correlation
    from core.correlator import enrich_timeline_with_mitre

    final_timeline = run_correlation(final_timeline)
    enrich_timeline_with_mitre(final_timeline)
    high_alert_count = sum(1 for e in final_timeline if e.get("high_alert"))

    # 7. Timestamp'e göre sırala (Tam-Saha > ATO > exfil > confirmed)
    final_timeline.sort(
        key=lambda e: (
            not e.get("full_spectrum_threat"),
            not e.get("account_takeover_threat"),
            not e.get("exfiltration_threat"),
            not e.get("confirmed_threat"),
            e.get("Timestamp", "") or "",
        )
    )
    confirmed_count = sum(1 for e in final_timeline if e.get("confirmed_threat"))

    # 8. Tablo olarak göster
    if not final_timeline:
        print("\n[!] Hic olay bulunamadi.")
        if not (getattr(args, "report", None) or getattr(args, "pdf", False)):
            return 0
        print("[*] Rapor talebi var — bos Storyline ile devam ediliyor.")

    try:
        from tabulate import tabulate

        headers = ["Timestamp", "Level", "RuleTitle", "Details"]
        rows = []
        for e in final_timeline:
            ts = (e.get("Timestamp") or "")[:19]
            lv = (e.get("Level") or "")[:8]
            rt = (e.get("RuleTitle") or "")[:45]
            dt = (e.get("Details") or "")[:50]
            if e.get("full_spectrum_threat"):
                rt = "[TAM SAHA] " + rt
            elif e.get("account_takeover_threat"):
                rt = "[BULUT ATO] " + rt
            elif e.get("exfiltration_threat"):
                rt = "[VERI SIZINTISI] " + rt
            elif e.get("confirmed_threat"):
                rt = "[KESINLESMIS] " + rt
            elif e.get("high_alert"):
                rt = "*** " + rt
            rows.append([ts, lv, rt, dt])

        print("\n" + "=" * 100)
        title = "BIRLESIK TIMELINE (Hayabusa + Chainsaw)"
        if volatility_results and volatility_results.get("success"):
            title += " + NETWORK_MEMORY + PROCESS_MEMORY"
        print(title)
        print("=" * 100)
        print(tabulate(rows, headers=headers, tablefmt="grid"))
        stats = f"\nToplam: {len(final_timeline)} olay | High Alert: {high_alert_count}"
        if confirmed_count:
            stats += f" | KESINLESMIS TEHDIT: {confirmed_count}"
        if account_takeover_threats:
            stats += f" | BULUT ATO: {len(account_takeover_threats)}"
        if full_spectrum_threats:
            stats += f" | TAM SAHA: {len(full_spectrum_threats)}"
        if exfiltration_threats:
            stats += f" | VERI SIZINTISI: {len(exfiltration_threats)}"
        print(stats)
    except ImportError:
        print("\n[*] Tablo icin: pip install tabulate")
        for e in final_timeline[:20]:
            print(f"  {e.get('Timestamp', '')} | {e.get('Level', '')} | {e.get('RuleTitle', '')} | {e.get('Details', '')[:40]}")
        if len(final_timeline) > 20:
            print(f"  ... ve {len(final_timeline) - 20} olay daha")

    # 9. HTML / PDF Storyline raporu (--report ve/veya --pdf)
    report_path_arg = getattr(args, "report", None)
    want_pdf = bool(getattr(args, "pdf", False))
    if report_path_arg is not None or want_pdf:
        from core.reporter import (
            DEFAULT_INCIDENT_RESPONSE_TITLE,
            generate_html_report,
            generate_pdf_report,
        )

        html_out = (
            Path(report_path_arg).resolve()
            if report_path_arg is not None
            else (results_dir / "diz_vaka_raporu_001.html")
        )
        pdf_out = results_dir / "diz_vaka_raporu_001.pdf"
        report_title = DEFAULT_INCIDENT_RESPONSE_TITLE
        report_subtitle = (
            "Disk · RAM · Ağ · Bulut · Mobil — core/correlator birleşik zaman çizelgesi ve Storyline PDF çıktısı"
        )

        rp = generate_html_report(
            final_timeline,
            html_out,
            title=report_title,
            subtitle=report_subtitle,
            mask_sensitive=True,
            confirmed_threats=confirmed_threats,
            exfiltration_threats=exfiltration_threats,
            account_takeover_threats=account_takeover_threats,
            full_spectrum_threats=full_spectrum_threats,
            cross_alignment=cross_alignment,
            results_dir_for_hashes=results_dir,
        )
        print(f"\n[+] HTML Storyline raporu: {rp}")

        if want_pdf:
            pdf_res = generate_pdf_report(
                final_timeline,
                pdf_out,
                html_path=html_out,
                title=report_title,
                subtitle=report_subtitle,
                mask_sensitive=True,
                confirmed_threats=confirmed_threats,
                exfiltration_threats=exfiltration_threats,
                account_takeover_threats=account_takeover_threats,
                full_spectrum_threats=full_spectrum_threats,
                cross_alignment=cross_alignment,
                results_dir_for_hashes=results_dir,
            )
            if pdf_res and pdf_res.exists():
                print(f"[+] PDF (diz_vaka_raporu_001.pdf): {pdf_res}")
            else:
                print(
                    "[!] PDF olusturulamadi. pip install weasyprint veya pdfkit+wKHTMLTOPDF deneyin."
                )

    # 10. DİZ-Analist (LLM saldırı senaryosu / dedektif raporu)
    if getattr(args, "diz_ai", False) or getattr(args, "ai_detective", False):
        from core.ai_analyst import run_diz_analyst

        det = bool(getattr(args, "ai_detective", False))
        print("\n[*] DİZ-Analist (LLM) calisiyor..." + (" [Dedektif modu]" if det else ""))
        ai_res = run_diz_analyst(
            provider=args.ai_provider,
            model=args.ai_model,
            detective_mode=det,
            alignment=cross_alignment,
        )
        if ai_res.get("success"):
            print(f"[+] Rapor: {ai_res.get('report_path')}")
            print(f"    ({ai_res.get('provider')} / {ai_res.get('model')})")
            n_pb = len((ai_res.get("intervention_playbook") or {}).get("steps") or [])
            if n_pb:
                print(f"[+] Müdahale Önerileri (Playbook): {n_pb} adım — data/results/diz_analyst/intervention_playbook.json")
        else:
            print(f"[!] DİZ-Analist: {ai_res.get('error', 'bilinmeyen hata')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
