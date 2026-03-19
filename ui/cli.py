"""
CLI Arayüzü - Komut satırı arayüzü
"""

import argparse
import logging
import sys
from pathlib import Path

# Proje kökünü path'e ekle
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.engine import DFIREngine


def setup_logging(verbose: bool = False) -> None:
    """Loglama ayarlarını yapar."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_list(args: argparse.Namespace, engine: DFIREngine) -> int:
    """Modülleri listeler."""
    modules = engine.list_available_modules()
    print("\n[*] Mevcut Moduller:\n")
    for m in modules:
        print(f"  • {m['name']}: {m['description']}")
        print(f"    Gerekli araçlar: {', '.join(m['required_tools']) or 'yok'}")
    return 0


def cmd_run(args: argparse.Namespace, engine: DFIREngine) -> int:
    """Tek modül çalıştırır."""
    evidence = Path(args.evidence) if args.evidence else None
    kwargs = {}
    if args.module == "ai_analyst":
        if getattr(args, "provider", None):
            kwargs["provider"] = args.provider
        if getattr(args, "model", None):
            kwargs["model"] = args.model
    try:
        result = engine.run_module(args.module, evidence, **kwargs)
        print(f"\n[OK] Modul tamamlandi: {result['module']}")
        print(f"   Durum: {result['status']}")
        print(f"   Çıktı: {result.get('output_path', '-')}")
        return 0 if result["status"] == "success" else 1
    except Exception as e:
        print(f"\n[HATA] {e}", file=sys.stderr)
        return 1


def cmd_pipeline(args: argparse.Namespace, engine: DFIREngine) -> int:
    """Pipeline çalıştırır."""
    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    evidence = Path(args.evidence) if args.evidence else None

    try:
        result = engine.run_pipeline(
            modules=modules,
            evidence_path=evidence,
            parse_to_supertimeline=not args.no_supertimeline,
        )
        print(f"\n[OK] Pipeline tamamlandi")
        print(f"   Çalışan modül sayısı: {result['modules_run']}")
        for r in result["results"]:
            status = "+" if r["status"] == "success" else "-"
            print(f"   {status} {r['module']}: {r['status']}")
        return 0
    except Exception as e:
        print(f"\n[HATA] {e}", file=sys.stderr)
        return 1


def main() -> int:
    """CLI ana giriş noktası."""
    parser = argparse.ArgumentParser(
        prog="dijital-iz-surucu",
        description="Dijital İz Sürücü - DFIR Framework",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı log")
    parser.add_argument(
        "-d",
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Veri dizini (varsayılan: data)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Komutlar")

    # list
    p_list = subparsers.add_parser("list", help="Mevcut modülleri listele")
    p_list.set_defaults(func=cmd_list)

    # run
    p_run = subparsers.add_parser("run", help="Tek modül çalıştır")
    p_run.add_argument("module", help="Modül adı (volatility, hayabusa, kape, ai_analyst)")
    p_run.add_argument("-e", "--evidence", help="Kanıt dosyası/dizini yolu")
    p_run.add_argument("--provider", choices=["openai", "ollama"], help="ai_analyst: openai veya ollama")
    p_run.add_argument("--model", help="ai_analyst: model adı (gpt-4o-mini, llama3.2 vb.)")
    p_run.set_defaults(func=cmd_run)

    # pipeline
    p_pipeline = subparsers.add_parser("pipeline", help="Modül pipeline'ı çalıştır")
    p_pipeline.add_argument(
        "modules",
        help="Virgülle ayrılmış modül listesi (örn: hayabusa,kape)",
    )
    p_pipeline.add_argument("-e", "--evidence", help="Kanıt dosyası/dizini yolu")
    p_pipeline.add_argument(
        "--no-supertimeline",
        action="store_true",
        help="SuperTimeline birleştirmeyi atla",
    )
    p_pipeline.set_defaults(func=cmd_pipeline)

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 0

    engine = DFIREngine(data_dir=args.data_dir)
    return args.func(args, engine)


if __name__ == "__main__":
    sys.exit(main())
