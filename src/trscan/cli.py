import argparse
import asyncio
import sys

from .scanner import WebSecurityScanner


def main():
    """CLI giriş noktası"""
    parser = argparse.ArgumentParser(
        description="TR-Pasif Web Güvenlik Skoru - Yasal ve etik pasif web güvenlik tarama aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  trscan scan https://example.com
  trscan scan https://example.com --output report.md --json report.json
  trscan scan https://example.com --shark-mode --max-requests 20
  trscan scan https://example.com --no-login-paths

Yasal Uyarı:
  Bu aracı sadece kendi sahip olduğunuz veya açıkça test izni aldığınız
  sistemler üzerinde kullanın. İzinsiz tarama yasa dışıdır.
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Komutlar")

    # Scan komutu
    scan_parser = subparsers.add_parser("scan", help="Web sitesini tara")

    # Konumsal argümanlar
    scan_parser.add_argument("url", help="Hedef URL (örn: https://example.com)")

    # Seçenekler
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Markdown rapor çıktı dosyası (örn: report.md)",
    )

    scan_parser.add_argument(
        "--json", type=str, default=None, help="JSON rapor çıktı dosyası (örn: report.json)"
    )

    scan_parser.add_argument(
        "--max-requests", type=int, default=15, help="Maksimum istek sayısı (varsayılan: 15)"
    )

    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Zaman aşımı süresi saniye cinsinden (varsayılan: 10)",
    )

    scan_parser.add_argument(
        "--no-polite", action="store_true", help="Polite mode'u kapat (yapmamanızı öneririz)"
    )

    scan_parser.add_argument(
        "--shark-mode", action="store_true", help="Shark Mode 🦈 (daha katı puanlama)"
    )

    scan_parser.add_argument(
        "--paths",
        type=str,
        nargs="+",
        default=None,
        help="Kontrol edilecek path'ler (varsayılan: /robots.txt, /sitemap.xml, /.well-known/security.txt, /login, /admin)",
    )

    scan_parser.add_argument(
        "--no-login-paths", action="store_true", help="/login ve /admin path kontrollerini yapma"
    )

    # Versiyon
    parser.add_argument("--version", action="version", version="TRScan v1.0.0")

    # Argümanları parse et
    args = parser.parse_args()

    # Komut yoksa help göster
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        # Tarama işlemini başlat
        run_scan(args)


def run_scan(args):
    """Tarama işlemini çalıştır"""

    # Başlık
    print("=" * 70)
    print("🔒 TR-Pasif Web Güvenlik Skoru v1.0.0")
    print("Yasal ve etik pasif web güvenlik tarama aracı")
    print("=" * 70)
    print()

    # Konfigürasyonu göster
    config = {
        "Hedef URL": args.url,
        "Maksimum İstek": args.max_requests,
        "Timeout": f"{args.timeout} saniye",
        "Polite Mode": "Kapalı" if args.no_polite else "Açık ✅",
        "Shark Mode": "Açık 🦈" if args.shark_mode else "Kapalı",
    }

    print("⚙️  Konfigürasyon:")
    for key, value in config.items():
        print(f"  • {key}: {value}")
    print()

    # Yasal uyarı
    print("⚠️  YASAL UYARI:")
    print("  Bu aracı sadece kendi sahip olduğunuz veya açıkça test izni aldığınız")
    print("  sistemler üzerinde kullanın. İzinsiz tarama yasa dışıdır.")
    print()

    # Kullanıcıdan onay iste (harici bir tool olmadan otomatik olarak devam edelim)
    # Gerçek kullanımda onay istenebilir ama şimdilik otomatik devam edelim

    # Scanner oluştur
    scanner = WebSecurityScanner(
        shark_mode=args.shark_mode,
        max_requests=args.max_requests,
        timeout=args.timeout,
        polite_mode=not args.no_polite,
        paths=args.paths,
        no_login_paths=args.no_login_paths,
    )

    # Asenkron tarama
    try:
        result = asyncio.run(scanner.scan(args.url))

        print()
        print("=" * 70)
        print("✅ Tarama Tamamlandı!")
        print("=" * 70)
        print()

        # Terminal raporu göster
        scanner.generate_terminal_report(result)

        # Raporları dosyalara kaydet
        if args.output:
            save_markdown_report(result, args.output)

        if args.json:
            save_json_report(result, args.json)

        # Çıktı dosyalarını göster
        if args.output or args.json:
            print()
            print("📁 Çıktı Dosyaları:")
            if args.output:
                print(f"  • Markdown: {args.output}")
            if args.json:
                print(f"  • JSON: {args.json}")
            print()

    except KeyboardInterrupt:
        print()
        print("❌ Tarama kullanıcı tarafından iptal edildi.")
        sys.exit(1)
    except Exception as e:
        print()
        print(f"❌ Hata: {str(e)}")
        sys.exit(1)


def save_markdown_report(result, filepath: str):
    """Markdown raporunu kaydet"""
    from .scanner import WebSecurityScanner

    # Geçici scanner oluştur (rapor üretmek için)
    scanner = WebSecurityScanner()

    markdown_content = scanner.generate_markdown_report(result)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"✅ Markdown raporu kaydedildi: {filepath}")


def save_json_report(result, filepath: str):
    """JSON raporunu kaydet"""
    from .scanner import WebSecurityScanner

    # Geçici scanner oluştur (rapor üretmek için)
    scanner = WebSecurityScanner()

    json_content = scanner.generate_json_report(result)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json_content)

    print(f"✅ JSON raporu kaydedildi: {filepath}")


if __name__ == "__main__":
    main()
