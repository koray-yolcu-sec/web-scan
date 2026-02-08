import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models.scan_result import Finding, ScanResult


class SecurityReporter:
    """Güvenlik raporu oluşturucu"""

    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.console = Console()

    def generate_terminal_report(self, result: ScanResult):
        """Terminal raporu oluştur (rich kullanarak)"""

        # Başlık
        title = "🔒 TR-Pasif Web Güvenlik Skoru Raporu"
        if self.shark_mode:
            title += " 🦈 (Shark Mode)"

        self.console.print(Panel(title, style="bold blue"))

        # Skor panel
        self._print_score_panel(result)

        # Önce bunları düzelt
        self._print_top_priorities(result)

        # Hızlı kazanımlar
        self._print_quick_wins(result)

        # Detaylı bulgular
        self._print_findings(result)

        # Kategori özeti
        self._print_categories_summary(result)

        # Skor anlamı
        self._print_score_meaning(result)

        # Yasal uyarı
        self._print_legal_warning()

    def _print_score_panel(self, result: ScanResult):
        """Skor panelini yazdır"""
        score_color = {"Kırmızı": "red", "Sarı": "yellow", "Yeşil": "green"}.get(
            result.score.color, "white"
        )

        score_text = Text(f"{result.score.score}/100", style=f"bold {score_color}")
        label_text = Text(f"({result.score.color} - {result.score.label})", style=f"{score_color}")

        panel = Panel(
            f"Güvenlik Skoru: {score_text}\n{label_text}", title="💯 Skor", border_style=score_color
        )

        self.console.print(panel)

    def _print_top_priorities(self, result: ScanResult):
        """Öncelik listesini yazdır"""
        if not result.top_priorities:
            return

        table = Table(title="🎯 Önce Bunları Düzelt", show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=3)
        table.add_column("Öncelik", style="red")

        for i, priority in enumerate(result.top_priorities, 1):
            table.add_row(str(i), priority)

        self.console.print(table)

    def _print_quick_wins(self, result: ScanResult):
        """Hızlı kazanımları yazdır"""
        if not result.quick_wins:
            return

        table = Table(
            title="⚡ Hızlı Kazanımlar (Quick Wins)", show_header=True, header_style="bold cyan"
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Kolay Düzeltme", style="green")

        for i, win in enumerate(result.quick_wins, 1):
            table.add_row(str(i), win)

        self.console.print(table)

    def _print_findings(self, result: ScanResult):
        """Bulguları yazdır"""
        if not result.findings:
            self.console.print("\n✅ Bulunmuş kritik güvenlik sorunu yok!", style="bold green")
            return

        # Bulguları önem sırasına göre grupla
        grouped = {"Kırmızı": [], "Sarı": [], "Yeşil": []}
        for finding in result.findings:
            grouped[finding.severity].append(finding)

        # Her grubu yazdır
        for severity in ["Kırmızı", "Sarı", "Yeşil"]:
            findings = grouped[severity]
            if not findings:
                continue

            severity_style = {"Kırmızı": "red", "Sarı": "yellow", "Yeşil": "green"}[severity]

            self.console.print(f"\n{'='*50}", style=severity_style)
            self.console.print(
                f"🔴 {severity} Bulgular ({len(findings)})", style=f"bold {severity_style}"
            )

            for i, finding in enumerate(findings, 1):
                self._print_finding(finding, i, severity_style)

    def _print_finding(self, finding: Finding, index: int, style: str):
        """Tekil bulgu yazdır"""
        panel_title = f"{index}. {finding.title}"

        content = f"""
**Önem:** {finding.severity} (-{abs(finding.score_impact)})

**Etki:**
{finding.description}

**Kanıt:**
{finding.evidence}

**Çözüm:**
{finding.solution}

**Mini Trick:**
{finding.mini_trick}

**Referans:**
{finding.reference}
"""

        panel = Panel(content.strip(), title=panel_title, border_style=style, padding=(0, 2))

        self.console.print(panel)

    def _print_categories_summary(self, result: ScanResult):
        """Kategori özetini yazdır"""
        table = Table(title="📊 Kategori Özeti", show_header=True, header_style="bold blue")
        table.add_column("Kategori", style="cyan")
        table.add_column("Sayı", style="white")

        for category, count in result.categories_summary.items():
            table.add_row(category, str(count))

        self.console.print(table)

    def _print_score_meaning(self, result: ScanResult):
        """Skor anlamını yazdır"""
        panel = Panel(
            result.score.meaning, title="💡 Bu Skor Ne Anlama Geliyor?", border_style="blue"
        )

        self.console.print(panel)

    def _print_legal_warning(self, result: ScanResult | None = None):
        """Yasal uyarı yazdır"""
        warning = """
⚠️  YASAL VE ETİK UYARI

Bu rapor sadece eğitim ve bilgilendirme amaçlıdır.
- Bu aracı sadece kendi sahip olduğunuz veya açıkça test izni aldığınız sistemlerde kullanın.
- Bu rapordaki bulgular profesyonel güvenlik uzmanları tarafından doğrulanmalıdır.
- Bu araç aktif saldırı yapmaz, sadece pasif testler uygular.
- Herhangi bir izin olmadan başkasına ait sistemlerde tarama yapmak yasa dışıdır.

Bu raporda belirtilen düzeltmeleri uygulamadan önce test ortamında deneyin.
"""

        panel = Panel(warning.strip(), title="⚖️  Hukuki Şeffaflık", border_style="yellow")

        self.console.print(panel)

    def generate_json_report(self, result: ScanResult) -> str:
        """JSON raporu oluştur"""
        report = {
            "scan_info": {
                "target_url": result.target_url,
                "scan_date": result.scan_date.isoformat(),
                "scan_duration_seconds": result.scan_duration_seconds,
                "shark_mode": result.shark_mode,
                "max_requests": result.max_requests,
                "timeout": result.timeout,
            },
            "score": {
                "score": result.score.score,
                "color": result.score.color,
                "label": result.score.label,
                "meaning": result.score.meaning,
            },
            "summary": {
                "quick_wins": result.quick_wins,
                "top_priorities": result.top_priorities,
                "categories_summary": result.categories_summary,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "score_impact": f.score_impact,
                    "description": f.description,
                    "evidence": f.evidence,
                    "solution": f.solution,
                    "mini_trick": f.mini_trick,
                    "reference": f.reference,
                    "category": f.category,
                }
                for f in result.findings
            ],
            "analysis": {
                "headers": result.headers.dict() if result.headers else None,
                "tls": result.tls.dict() if result.tls else None,
                "dns": result.dns.dict() if result.dns else None,
                "page": result.page.dict() if result.page else None,
            },
            "additional_info": {
                "robots_txt_exists": result.robots_txt_exists,
                "sitemap_xml_exists": result.sitemap_xml_exists,
                "security_txt_exists": result.security_txt_exists,
                "login_path_exists": result.login_path_exists,
                "admin_path_exists": result.admin_path_exists,
            },
        }

        return json.dumps(report, indent=2, ensure_ascii=False, default=str)

    def generate_markdown_report(self, result: ScanResult) -> str:
        """Markdown raporu oluştur"""
        md_lines = []

        # Başlık
        md_lines.append("# 🔒 TR-Pasif Web Güvenlik Skoru Raporu")
        if self.shark_mode:
            md_lines.append("🦈 Shark Mode Aktif\n")

        md_lines.append(f"**Hedef:** {result.target_url}")
        md_lines.append(f"**Tarih:** {result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
        md_lines.append(f"Süre: {result.scan_duration_seconds:.2f} saniye\n")

        # Skor
        score_emoji = {"Kırmızı": "🔴", "Sarı": "🟡", "Yeşil": "🟢"}[result.score.color]
        md_lines.append("## 💯 Güvenlik Skoru\n")
        md_lines.append(
            f"{score_emoji} **{result.score.score}/100** ({result.score.color} - {result.score.label})\n"
        )

        # Skor anlamı
        md_lines.append("### 💡 Bu Skor Ne Anlama Geliyor?")
        md_lines.append(f"{result.score.meaning}\n")

        # Önce bunları düzelt
        if result.top_priorities:
            md_lines.append("## 🎯 Önce Bunları Düzelt\n")
            for i, priority in enumerate(result.top_priorities, 1):
                md_lines.append(f"{i}. {priority}")
            md_lines.append("")

        # Hızlı kazanımlar
        if result.quick_wins:
            md_lines.append("## ⚡ Hızlı Kazanımlar (Quick Wins)\n")
            for i, win in enumerate(result.quick_wins, 1):
                md_lines.append(f"{i}. {win}")
            md_lines.append("")

        # Bulgular
        if result.findings:
            # Bulguları grupla
            grouped = {"Kırmızı": [], "Sarı": [], "Yeşil": []}
            for finding in result.findings:
                grouped[finding.severity].append(finding)

            # Her grubu yazdır
            for severity in ["Kırmızı", "Sarı", "Yeşil"]:
                findings = grouped[severity]
                if not findings:
                    continue

                severity_emoji = {"Kırmızı": "🔴", "Sarı": "🟡", "Yeşil": "🟢"}[severity]
                md_lines.append(f"## {severity_emoji} {severity} Bulgular ({len(findings)})\n")

                for i, finding in enumerate(findings, 1):
                    md_lines.append(f"### {i}. {finding.title}")
                    md_lines.append(
                        f"**Önem:** {finding.severity} (-{abs(finding.score_impact)})\n"
                    )
                    md_lines.append(f"**Etki:** {finding.description}\n")
                    md_lines.append("**Kanıt:**")
                    md_lines.append(f"```\n{finding.evidence}\n```\n")
                    md_lines.append("**Çözüm:**")
                    md_lines.append(f"{finding.solution}\n")
                    md_lines.append(f"**Mini Trick:** {finding.mini_trick}\n")
                    md_lines.append(f"**Referans:** {finding.reference}\n")
        else:
            md_lines.append("## ✅ Güvenlik Bulguları\n")
            md_lines.append("Kritik güvenlik sorunu bulunamadı!\n")

        # Kategori özeti
        md_lines.append("## 📊 Kategori Özeti\n")
        md_lines.append("| Kategori | Sayı |")
        md_lines.append("|----------|------|")
        for category, count in result.categories_summary.items():
            md_lines.append(f"| {category} | {count} |")
        md_lines.append("")

        # Ek bilgiler
        md_lines.append("## ℹ️  Ek Bilgiler\n")
        md_lines.append(f"- Robots.txt: {'✅ Var' if result.robots_txt_exists else '❌ Yok'}")
        md_lines.append(f"- Sitemap.xml: {'✅ Var' if result.sitemap_xml_exists else '❌ Yok'}")
        md_lines.append(f"- Security.txt: {'✅ Var' if result.security_txt_exists else '❌ Yok'}")
        md_lines.append(f"- /login: {'✅ Var' if result.login_path_exists else '❌ Yok'}")
        md_lines.append(f"- /admin: {'✅ Var' if result.admin_path_exists else '❌ Yok'}")
        md_lines.append("")

        # Quick Fix Checklist
        md_lines.append("## 🛠️  Quick Fix Checklist\n")
        md_lines.append("### Nginx\n")
        md_lines.append("```nginx\n")
        md_lines.append("# HTTPS redirect\n")
        md_lines.append("server {\n")
        md_lines.append("    listen 80;\n")
        md_lines.append("    server_name example.com;\n")
        md_lines.append("    return 301 https://$host$request_uri;\n")
        md_lines.append("}\n\n")
        md_lines.append("# Security headers\n")
        md_lines.append(
            "add_header Strict-Transport-Security &quot;max-age=31536000; includeSubDomains&quot; always;\n"
        )
        md_lines.append("add_header X-Frame-Options &quot;SAMEORIGIN&quot; always;\n")
        md_lines.append("add_header X-Content-Type-Options &quot;nosniff&quot; always;\n")
        md_lines.append(
            "add_header Referrer-Policy &quot;strict-origin-when-cross-origin&quot; always;\n"
        )
        md_lines.append("# Content-Security-Policy kendi ihtiyacınıza göre ayarlayın\n")
        md_lines.append("```\n")

        md_lines.append("### Apache\n")
        md_lines.append("```apache\n")
        md_lines.append("# HTTPS redirect\n")
        md_lines.append("<VirtualHost *:80>\n")
        md_lines.append("    ServerName example.com\n")
        md_lines.append("    Redirect permanent / https://example.com/\n")
        md_lines.append("</VirtualHost>\n\n")
        md_lines.append("# Security headers\n")
        md_lines.append("<IfModule mod_headers.c>\n")
        md_lines.append(
            "    Header always set Strict-Transport-Security &quot;max-age=31536000; includeSubDomains&quot;\n"
        )
        md_lines.append("    Header always set X-Frame-Options &quot;SAMEORIGIN&quot;\n")
        md_lines.append("    Header always set X-Content-Type-Options &quot;nosniff&quot;\n")
        md_lines.append(
            "    Header always set Referrer-Policy &quot;strict-origin-when-cross-origin&quot;\n"
        )
        md_lines.append("</IfModule>\n")
        md_lines.append("```\n")

        md_lines.append("### Cloudflare\n")
        md_lines.append("- Cloudflare'da bu header'lar otomatik olarak eklenir\n")
        md_lines.append("- Transform Rules > Modify Response Header ile ekleyebilirsiniz\n")
        md_lines.append("- Page Rules ile HTTPS zorlama yapabilirsiniz\n")
        md_lines.append("")

        # Bu tool ne yapmaz
        md_lines.append("## ⚖️  Bu Tool Ne YAPMAZ\n")
        md_lines.append("- ❌ Aktif saldırı veya exploit denemeleri\n")
        md_lines.append("- ❌ Brute-force veya credential stuffing\n")
        md_lines.append("- ❌ SQLi, XSS gibi istismar testleri\n")
        md_lines.append("- ❌ Agresif tarama veya rate limit zorlama\n")
        md_lines.append("- ❌ Gizli dizin brute-force (yoğun)\n")
        md_lines.append("")

        md_lines.append("## ✅ Bu Tool Ne Yapar\n")
        md_lines.append("- ✅ Pasif HTTP/HTTPS analiz\n")
        md_lines.append("- ✅ Header ve cookie kontrol\n")
        md_lines.append("- ✅ DNS güvenlik kayıtları\n")
        md_lines.append("- ✅ HTTPS/TLS sertifika kontrol\n")
        md_lines.append("- ✅ Sayfa yapısı ve frontend güvenlik sinyalleri\n")
        md_lines.append("- ✅ Yasal ve etik sınırlar içinde kalır\n")
        md_lines.append("")

        # Legal uyarı
        md_lines.append("## ⚠️  YASAL VE ETİK UYARI\n")
        md_lines.append("Bu rapor sadece eğitim ve bilgilendirme amaçlıdır.\n")
        md_lines.append(
            "- Bu aracı **sadece kendi sahip olduğunuz** veya **açıkça test izni aldığınız** sistemlerde kullanın.\n"
        )
        md_lines.append(
            "- Bu rapordaki bulgular profesyonel güvenlik uzmanları tarafından doğrulanmalıdır.\n"
        )
        md_lines.append(
            "- Herhangi bir izin olmadan başkasına ait sistemlerde tarama yapmak **yasa dışıdır** ve suç teşkil eder.\n"
        )
        md_lines.append(
            "- Kullanıcı bu aracı kullanarak herhangi bir yasayı veya etik kuralı ihlal etmekten tamamen sorumludur.\n"
        )
        md_lines.append("")

        return "\n".join(md_lines)
