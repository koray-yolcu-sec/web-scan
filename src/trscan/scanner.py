from datetime import datetime
from urllib.parse import urlparse

from .analyzers import (
    CookieAnalyzer,
    DNSAnalyzer,
    HeaderAnalyzer,
    PageAnalyzer,
    TLSAnalyzer,
)
from .fetcher import DNSFetcher, HTTPFetcher
from .models import Finding, ScanResult
from .reporter import SecurityReporter
from .scorer import SecurityScorer


class WebSecurityScanner:
    """Web güvenlik tarayıcısı - Ana koordinatör"""

    def __init__(
        self,
        shark_mode: bool = False,
        max_requests: int = 15,
        timeout: int = 10,
        polite_mode: bool = True,
        paths: list[str] | None = None,
        no_login_paths: bool = False,
    ):
        self.shark_mode = shark_mode
        self.max_requests = max_requests
        self.timeout = timeout
        self.polite_mode = polite_mode
        self.paths = paths
        self.no_login_paths = no_login_paths

        # Fetcher'lar
        self.http_fetcher = HTTPFetcher(
            timeout=timeout, max_requests=max_requests, polite_mode=polite_mode
        )
        self.dns_fetcher = DNSFetcher(timeout=timeout)

        # Analizciler
        self.header_analyzer = HeaderAnalyzer(shark_mode=shark_mode)
        self.cookie_analyzer = CookieAnalyzer(shark_mode=shark_mode)
        self.tls_analyzer = TLSAnalyzer(shark_mode=shark_mode)
        self.dns_analyzer = DNSAnalyzer(shark_mode=shark_mode)
        self.page_analyzer = PageAnalyzer(shark_mode=shark_mode)

        # Skorlayıcı
        self.scorer = SecurityScorer(shark_mode=shark_mode)

        # Raporlayıcı
        self.reporter = SecurityReporter(shark_mode=shark_mode)

    async def scan(self, target_url: str) -> ScanResult:
        """
        Web sitesini tarar

        Args:
            target_url: Hedef URL

        Returns:
            ScanResult: Tam tarama sonucu
        """
        start_time = datetime.now()

        # URL'i normalize et
        target_url = self._normalize_url(target_url)

        # Domain'i çıkar
        domain = urlparse(target_url).netloc

        # Tüm bulgular
        all_findings: list[Finding] = []

        # 1. Ana sayfayı çek
        print(f"[🌐] Ana sayfa çekiliyor: {target_url}")
        main_page_result = await self.http_fetcher.fetch_main_page(target_url)

        if not main_page_result or main_page_result["status_code"] is None:
            raise Exception(f"Hata: {target_url} erişilemedi")

        print(f"[✅] Ana sayfa çekildi (Status: {main_page_result['status_code']})")

        # 2. Cookie'leri analiz et
        print("[🍪] Cookie'ler analiz ediliyor...")
        cookie_infos, cookie_findings = self.cookie_analyzer.analyze(main_page_result["cookies"])
        all_findings.extend(cookie_findings)
        print(f"[✅] {len(cookie_infos)} cookie analiz edildi")

        # 3. Header'ları analiz et
        print("[📋] Header'lar analiz ediliyor...")
        header_analysis, header_findings = self.header_analyzer.analyze(main_page_result["headers"])
        all_findings.extend(header_findings)
        print("[✅] Header'lar analiz edildi")

        # 4. TLS/HTTPS analiz et
        print("[🔒] TLS/HTTPS analiz ediliyor...")
        tls_info, tls_findings = self.tls_analyzer.analyze(main_page_result)
        all_findings.extend(tls_findings)
        print("[✅] TLS/HTTPS analiz edildi")

        # 5. Sayfa yapısını analiz et
        print("[📄] Sayfa yapısı analiz ediliyor...")
        page_info, page_findings = self.page_analyzer.analyze(
            main_page_result["content"], main_page_result["final_url"], main_page_result["headers"]
        )
        all_findings.extend(page_findings)
        print("[✅] Sayfa yapısı analiz edildi")

        # 6. Ek path'leri kontrol et
        default_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
        if not self.no_login_paths:
            default_paths.extend(["/login", "/admin"])

        paths_to_check = self.paths if self.paths else default_paths

        print(f"[🔍] {len(paths_to_check)} path kontrol ediliyor...")
        paths_result = await self.http_fetcher.fetch_additional_paths(
            main_page_result["final_url"], paths_to_check
        )
        print("[✅] Path'ler kontrol edildi")

        # Path sonuçlarını kaydet
        robots_txt_exists = paths_result.get("/robots.txt", {}).get("exists", False)
        robots_txt_content = paths_result.get("/robots.txt", {}).get("content", "")
        sitemap_xml_exists = paths_result.get("/sitemap.xml", {}).get("exists", False)
        security_txt_exists = paths_result.get("/.well-known/security.txt", {}).get("exists", False)
        security_txt_content = paths_result.get("/.well-known/security.txt", {}).get("content", "")
        login_path_exists = paths_result.get("/login", {}).get("exists", False)
        admin_path_exists = paths_result.get("/admin", {}).get("exists", False)

        # 7. DNS güvenlik kayıtlarını analiz et
        print("[🌐] DNS güvenlik kayıtları analiz ediliyor...")
        dns_records = self.dns_fetcher.fetch_all_records(domain)
        dns_info, dns_findings = self.dns_analyzer.analyze(dns_records)
        all_findings.extend(dns_findings)
        print("[✅] DNS kayıtları analiz edildi")

        # 8. Skor hesapla
        print("[💯] Güvenlik skoru hesaplanıyor...")

        # Score impact'ları topla
        score_impacts = [f.score_impact for f in all_findings]

        security_score, categories_summary, quick_wins, top_priorities = (
            self.scorer.calculate_score(all_findings, {}, score_impacts)  # categories placeholder
        )
        print(f"[✅] Skor hesaplandı: {security_score.score}/100 ({security_score.color})")

        # Tarama süresini hesapla
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()

        # Sonucu oluştur
        result = ScanResult(
            target_url=target_url,
            scan_date=start_time,
            scan_duration_seconds=scan_duration,
            score=security_score,
            findings=all_findings,
            headers=header_analysis,
            cookies=cookie_infos,
            tls=tls_info,
            dns=dns_info,
            page=page_info,
            robots_txt_exists=robots_txt_exists,
            robots_txt_content=robots_txt_content if robots_txt_exists else None,
            sitemap_xml_exists=sitemap_xml_exists,
            security_txt_exists=security_txt_exists,
            security_txt_content=security_txt_content if security_txt_exists else None,
            login_path_exists=login_path_exists,
            admin_path_exists=admin_path_exists,
            shark_mode=self.shark_mode,
            max_requests=self.max_requests,
            timeout=self.timeout,
            quick_wins=quick_wins,
            top_priorities=top_priorities,
            categories_summary=categories_summary,
        )

        return result

    def _normalize_url(self, url: str) -> str:
        """URL'i normalize et"""
        url = url.strip()

        if not url.startswith(("http://", "https://")):
            # HTTPS varsayılan
            url = "https://" + url

        return url

    def generate_terminal_report(self, result: ScanResult):
        """Terminal raporu oluştur"""
        self.reporter.generate_terminal_report(result)

    def generate_json_report(self, result: ScanResult) -> str:
        """JSON raporu oluştur"""
        return self.reporter.generate_json_report(result)

    def generate_markdown_report(self, result: ScanResult) -> str:
        """Markdown raporu oluştur"""
        return self.reporter.generate_markdown_report(result)
