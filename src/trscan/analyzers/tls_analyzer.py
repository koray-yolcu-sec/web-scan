from datetime import datetime

from ..models.scan_result import Finding, TLSInfo


class TLSAnalyzer:
    """TLS/Sertifika analizcisi"""

    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.findings: list[Finding] = []

    def analyze(self, fetcher_result: dict) -> tuple[TLSInfo, list[Finding]]:
        """
        TLS/HTTPS durumunu analiz eder

        Args:
            fetcher_result: HTTP fetcher sonucu

        Returns:
            (TLSInfo, List[Finding])
        """
        self.findings = []

        tls_info = TLSInfo(
            https_enabled=fetcher_result.get("https_enabled", False),
            http_accessible=fetcher_result.get("http_accessible", False),
            certificate_valid=False,
            certificate_issuer=None,
            certificate_subject=None,
            certificate_expiry_date=None,
            certificate_expiry_days=None,
            tls_version=None,
            alpn_protocol=None,
        )

        # HTTPS kontrolü
        if not tls_info.https_enabled:
            self.findings.append(
                Finding(
                    title="HTTPS Kullanılmıyor",
                    severity="Kırmızı",
                    score_impact=-35,
                    description="Site HTTP üzerinden erişilebilir. Tüm trafiği şifrelemek için HTTPS kullanın.",
                    evidence="URL Scheme: http://",
                    solution="1. SSL sertifikası alın (ücretsiz: Let's Encrypt)\n2. Sunucuda HTTPS'i aktif edin\n3. HTTP'den HTTPS'e zorunlu redirect yapın",
                    mini_trick="Let's Encrypt ücretsiz ve otomatik yenilenen sertifika sağlar",
                    reference="OWASP Transport Layer Protection",
                    category="tls",
                )
            )
            return tls_info, self.findings

        # Sertifika bilgileri
        # Not: httpx ile sertifika detaylarına erişim sınırlı
        # Bu yüzden temel kontroller yapıyoruz

        # HTTP accessible kontrolü (HTTPS açıkken HTTP de açık mı?)
        if tls_info.http_accessible:
            self.findings.append(
                Finding(
                    title="HTTP Portu Açık (HTTPS Var)",
                    severity="Sarı",
                    score_impact=-5,
                    description="HTTPS kullanılsa da HTTP portu (80) da açık. Redirect yapılmıyor olabilir.",
                    evidence="HTTP (port 80): erişilebilir",
                    solution="1. HTTP'den HTTPS'e 301 redirect yapın\n2. Sadece HTTPS'i kabul edin",
                    mini_trick="Nginx için: return 301 https://$host$request_uri;",
                    reference="OWASP Transport Layer Protection",
                    category="tls",
                )
            )

        # TLS version sinyali (header'lardan)
        # Not: Bu temel bir kontrol, gerçek TLS version kontrolü için daha derin analiz gerekir
        # httpx tarafından desteklenen ALPN protokolü
        # Bu kısımda sadece genel bulgular ekliyoruz

        # Güvenli bağlantı için genel bulgu
        if tls_info.https_enabled:
            self.findings.append(
                Finding(
                    title="HTTPS Kullanılıyor (İyi)",
                    severity="Yeşil",
                    score_impact=0,
                    description="Site HTTPS kullanıyor, trafiğiniz şifreli.",
                    evidence="URL Scheme: https://",
                    solution="HTTPS'i koruyun, HTTP redirect'i ekleyin, HSTS kullanın",
                    mini_trick="HTTPS + HSTS + Redirect = Güvenli üçlü",
                    reference="OWASP Transport Layer Protection",
                    category="tls",
                )
            )

        return tls_info, self.findings

    def _check_certificate_expiry(self, expiry_date: datetime | None) -> tuple[bool, int | None]:
        """
        Sertifika bitiş tarihini kontrol et

        Returns:
            (is_valid, days_until_expiry)
        """
        if not expiry_date:
            return False, None

        today = datetime.now()
        days_until_expiry = (expiry_date - today).days

        is_valid = days_until_expiry > 0
        return is_valid, days_until_expiry

    def analyze_certificate_details(self, cert_info: dict) -> list[Finding]:
        """
        Detaylı sertifika analizi (eğer erişilebilirse)

        Args:
            cert_info: Sertifika bilgileri

        Returns:
            List[Finding]
        """
        findings = []


        expiry_date = cert_info.get("expiry_date")

        # Sertifika bitiş kontrolü
        if expiry_date:
            is_valid, days_until_expiry = self._check_certificate_expiry(expiry_date)

            if not is_valid:
                findings.append(
                    Finding(
                        title="SSL Sertifikası Süresi Dolmuş",
                        severity="Kırmızı",
                        score_impact=-20,
                        description=f"SSL sertifikası {abs(days_until_expiry)} gün önce doldu.",
                        evidence=f"Certificate Expiry: {expiry_date}",
                        solution="1. Yeni SSL sertifikası alın\n2. Sertifikayı yükleyin",
                        mini_trick="Let's Encrypt otomatik yenilenme özelliği var",
                        reference="OWASP SSL/TLS",
                        category="tls",
                    )
                )
            elif days_until_expiry < 30:
                findings.append(
                    Finding(
                        title="SSL Sertifikası Yakında Dolacak",
                        severity="Sarı",
                        score_impact=-5,
                        description=f"SSL sertifikası {days_until_expiry} gün içinde dolacak.",
                        evidence=f"Certificate Expiry: {expiry_date}",
                        solution="1. Sertifikayı yenileyin\n2. Otomatik yenileme ayarlayın",
                        mini_trick="Yenileme sürecini takviminize ekleyin",
                        reference="OWASP SSL/TLS",
                        category="tls",
                    )
                )

        return findings
