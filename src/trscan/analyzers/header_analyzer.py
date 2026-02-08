import re

from ..models.scan_result import Finding, HeaderAnalysis


class HeaderAnalyzer:
    """HTTP header güvenlik analizcisi"""

    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.findings: list[Finding] = []

    def analyze(self, headers: dict) -> tuple[HeaderAnalysis, list[Finding]]:
        """
        HTTP header'larını analiz eder

        Returns:
            (HeaderAnalysis, List[Finding])
        """
        analysis = HeaderAnalysis(
            csp_present=False,
            csp_has_default_src=False,
            csp_has_unsafe_inline=False,
            csp_has_unsafe_eval=False,
            csp_has_wildcard=False,
            csp_has_frame_ancestors=False,
            csp_quality_score=0,
            hsts_present=False,
            hsts_max_age=None,
            hsts_include_subdomains=False,
            hsts_preload=False,
            x_frame_options_present=False,
            x_frame_options_value=None,
            x_content_type_options_present=False,
            referrer_policy_present=False,
            referrer_policy_value=None,
            permissions_policy_present=False,
            permissions_policy_policies=[],
            cross_origin_opener_policy_present=False,
            cross_origin_embedder_policy_present=False,
            cross_origin_resource_policy_present=False,
            cache_control_present=False,
            cache_control_value=None,
            server_header=None,
            x_powered_by=None,
            cors_origin=None,
            cors_credentials=False,
        )

        self.findings = []

        # Header isimlerini normalize et (lowercase)
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Her header'ı analiz et
        self._analyze_csp(normalized_headers.get("content-security-policy", ""), analysis)
        self._analyze_hsts(normalized_headers.get("strict-transport-security", ""), analysis)
        self._analyze_x_frame_options(normalized_headers.get("x-frame-options", ""), analysis)
        self._analyze_x_content_type_options(
            normalized_headers.get("x-content-type-options", ""), analysis
        )
        self._analyze_referrer_policy(normalized_headers.get("referrer-policy", ""), analysis)
        self._analyze_permissions_policy(normalized_headers.get("permissions-policy", ""), analysis)
        self._analyze_cross_origin_policies(normalized_headers, analysis)
        self._analyze_cache_control(normalized_headers.get("cache-control", ""), analysis)
        self._analyze_server_headers(normalized_headers, analysis)
        self._analyze_cors(normalized_headers, analysis)

        return analysis, self.findings

    def _analyze_csp(self, csp_header: str, analysis: HeaderAnalysis):
        """Content-Security-Policy analizi"""
        if not csp_header:
            analysis.csp_present = False
            self.findings.append(
                Finding(
                    title="Content-Security-Policy (CSP) Eksik",
                    severity="Kırmızı",
                    score_impact=-10,
                    description="Site, Content-Security-Policy başlığı içermiyor. Bu durum, XSS saldırılarına karşı savunmasızlık yaratır.",
                    evidence="Content-Security-Policy: (yok)",
                    solution="1. Sunucu konfigürasyonuna CSP header ekleyin\n2. default-src 'self' ile başlayın\n3. Gereksiz kaynakları whitelist'e ekleyin\n4. unsafe-inline ve unsafe-eval kullanmaktan kaçının",
                    mini_trick="Emin değilseniz, önce 'Report-Only' modunda test edin: Content-Security-Policy-Report-Only",
                    reference="OWASP Content Security Policy",
                    category="header",
                )
            )
            return

        analysis.csp_present = True

        # CSP kalite analiz
        directives = csp_header.split(";")
        quality_score = 0

        for directive in directives:
            directive = directive.strip().lower()

            if "default-src" in directive:
                analysis.csp_has_default_src = True
                quality_score += 20

            if "'unsafe-inline'" in directive:
                analysis.csp_has_unsafe_inline = True
                quality_score -= 30

            if "'unsafe-eval'" in directive:
                analysis.csp_has_unsafe_eval = True
                quality_score -= 20

            if "*:" in directive or directive.startswith("*"):
                analysis.csp_has_wildcard = True
                quality_score -= 25

            if "frame-ancestors" in directive:
                analysis.csp_has_frame_ancestors = True
                quality_score += 15

        analysis.csp_quality_score = max(0, min(100, quality_score))

        # Bulgu ekle
        if analysis.csp_quality_score < 60:
            self.findings.append(
                Finding(
                    title="Content-Security-Policy (CSP) Kalitesi Düşük",
                    severity="Sarı",
                    score_impact=-5,
                    description=f"CSP var ama kalitesi düşük (skor: {analysis.csp_quality_score}/100). {self._get_csp_quality_description(analysis)}",
                    evidence=f"Content-Security-Policy: {csp_header[:200]}...",
                    solution="1. unsafe-inline ve unsafe-eval'i kaldırın\n2. Wildcard kullanımını azaltın\n3. default-src 'self' olarak ayarlayın\n4. frame-ancestors ekleyin",
                    mini_trick="CSP nonce veya hash kullanarak inline script'lere izin verebilirsiniz",
                    reference="OWASP CSP Best Practices",
                    category="header",
                )
            )

    def _get_csp_quality_description(self, analysis: HeaderAnalysis) -> str:
        """CSP kalite açıklaması"""
        issues = []
        if analysis.csp_has_unsafe_inline:
            issues.append("unsafe-inline var")
        if analysis.csp_has_unsafe_eval:
            issues.append("unsafe-eval var")
        if analysis.csp_has_wildcard:
            issues.append("wildcard var")
        if not analysis.csp_has_default_src:
            issues.append("default-src yok")

        return ", ".join(issues)

    def _analyze_hsts(self, hsts_header: str, analysis: HeaderAnalysis):
        """HTTP Strict Transport Security analizi"""
        if not hsts_header:
            analysis.hsts_present = False
            self.findings.append(
                Finding(
                    title="Strict-Transport-Security (HSTS) Eksik",
                    severity="Kırmızı",
                    score_impact=-10,
                    description="Site, HSTS başlığı içermiyor. Bu durum, MITM saldırılarına ve SSL stripping'e karşı savunmasızdır.",
                    evidence="Strict-Transport-Security: (yok)",
                    solution="1. Sunucu konfigürasyonuna HSTS header ekleyin\n2. min 6 ay (15768000 saniye) max-age kullanın\n3. includeSubDomains ekleyin\n4. Testten sonra preload'ı ekleyin",
                    mini_trick="Önce max-age=300 ile test edin, sorunsuzsa 1 yıla çıkarın",
                    reference="OWASP HSTS",
                    category="header",
                )
            )
            return

        analysis.hsts_present = True

        # HSTS parametrelerini parse et
        directives = hsts_header.split(";")
        for directive in directives:
            directive = directive.strip().lower()

            if directive.startswith("max-age="):
                try:
                    analysis.hsts_max_age = int(directive.split("=")[1])
                except:
                    pass

            if "includesubdomains" in directive:
                analysis.hsts_include_subdomains = True

            if "preload" in directive:
                analysis.hsts_preload = True

        # HSTS kalite kontrolü
        issues = []
        score_impact = 0

        if not analysis.hsts_max_age or analysis.hsts_max_age < 31536000:  # 1 yıldan az
            issues.append("max-age çok kısa")
            score_impact -= 3

        if not analysis.hsts_include_subdomains:
            issues.append("includeSubDomains yok")
            score_impact -= 2

        if not analysis.hsts_preload:
            issues.append("preload yok")
            score_impact -= 1

        if issues and score_impact != 0:
            self.findings.append(
                Finding(
                    title="HSTS Konfigürasyonu İyileştirilebilir",
                    severity="Sarı",
                    score_impact=score_impact,
                    description=f"HSTS var ama {', '.join(issues)}",
                    evidence=f"Strict-Transport-Security: {hsts_header}",
                    solution="1. max-age'i en az 31536000 (1 yıl) yapın\n2. includeSubDomains ekleyin\n3. https://hstspreload.org/'e başvurun",
                    mini_trick="max-age=31536000; includeSubDomains; preload ideal konfigürasyon",
                    reference="OWASP HSTS Best Practices",
                    category="header",
                )
            )

    def _analyze_x_frame_options(self, xfo_header: str, analysis: HeaderAnalysis):
        """X-Frame-Options analizi"""
        if not xfo_header:
            analysis.x_frame_options_present = False
            self.findings.append(
                Finding(
                    title="X-Frame-Options veya frame-ancestors Eksik",
                    severity="Sarı",
                    score_impact=-8,
                    description="Site, clickjacking koruması yok. Saldırganlar siteyi iframe içine gömebilir.",
                    evidence="X-Frame-Options: (yok) | frame-ancestors: (yok)",
                    solution="1. X-Frame-Options: DENY veya SAMEORIGIN ekleyin\n2. Veya CSP'de frame-ancestors kullanın",
                    mini_trick="DENY en güvenli, SAMEORIGIN sadece kendi domaininden iframe'e izin verir",
                    reference="OWASP Clickjacking",
                    category="header",
                )
            )
            return

        analysis.x_frame_options_present = True
        analysis.x_frame_options_value = xfo_header.upper()

        if "ALLOWALL" in xfo_header.upper():
            self.findings.append(
                Finding(
                    title="X-Frame-Options: ALLOWALL Riskli",
                    severity="Sarı",
                    score_impact=-5,
                    description="X-Frame-Options: ALLOWALL, tüm sitelerin iframe içine almaya izin verir.",
                    evidence=f"X-Frame-Options: {xfo_header}",
                    solution="X-Frame-Options: DENY veya SAMEORIGIN kullanın",
                    mini_trick="Her zaman DENY veya SAMEORIGIN kullanın, ALLOWALL kullanmayın",
                    reference="OWASP Clickjacking",
                    category="header",
                )
            )

    def _analyze_x_content_type_options(self, xcto_header: str, analysis: HeaderAnalysis):
        """X-Content-Type-Options analizi"""
        if not xcto_header or "nosniff" not in xcto_header.lower():
            analysis.x_content_type_options_present = False
            self.findings.append(
                Finding(
                    title="X-Content-Type-Options: nosniff Eksik",
                    severity="Sarı",
                    score_impact=-5,
                    description="Browser'ların MIME type sniffing yapmasına izin verir, bu XSS riski oluşturabilir.",
                    evidence="X-Content-Type-Options: (yok veya nosniff değil)",
                    solution="X-Content-Type-Options: nosniff ekleyin",
                    mini_trick="Bu header çok basit ama kritik, mutlaka ekleyin",
                    reference="OWASP Content Type",
                    category="header",
                )
            )
            return

        analysis.x_content_type_options_present = True

    def _analyze_referrer_policy(self, referrer_header: str, analysis: HeaderAnalysis):
        """Referrer-Policy analizi"""
        if not referrer_header:
            analysis.referrer_policy_present = False
            self.findings.append(
                Finding(
                    title="Referrer-Policy Eksik",
                    severity="Sarı",
                    score_impact=-4,
                    description="Referrer bilgisi dış sitelere sızabilir, gizlilik sorununa yol açabilir.",
                    evidence="Referrer-Policy: (yok)",
                    solution="Referrer-Policy: strict-origin-when-cross-origin kullanın",
                    mini_trick="strict-origin-when-cross-origin, güvenlik ve UX dengesi için ideal",
                    reference="OWASP Referrer Policy",
                    category="header",
                )
            )
            return

        analysis.referrer_policy_present = True
        analysis.referrer_policy_value = referrer_header

        # Gevşek politikaları kontrol et
        loose_policies = ["no-referrer-when-downgrade", "unsafe-url", ""]
        if referrer_header.lower() in loose_policies:
            self.findings.append(
                Finding(
                    title="Referrer-Policy Çok Gevşek",
                    severity="Sarı",
                    score_impact=-2,
                    description="Referrer-Policy çok gevşek, fazla bilgi paylaşıyor.",
                    evidence=f"Referrer-Policy: {referrer_header}",
                    solution="Referrer-Policy: strict-origin-when-cross-origin kullanın",
                    mini_trick="strict-origin-when-cross-origin, no-referrer'den daha az agresif",
                    reference="OWASP Referrer Policy",
                    category="header",
                )
            )

    def _analyze_permissions_policy(self, pp_header: str, analysis: HeaderAnalysis):
        """Permissions-Policy analizi"""
        if not pp_header:
            analysis.permissions_policy_present = False
            self.findings.append(
                Finding(
                    title="Permissions-Policy Eksik",
                    severity="Sarı",
                    score_impact=-3,
                    description="Browser API'lerine (camera, microphone, geolocation vb.) gereksiz izin verilebilir.",
                    evidence="Permissions-Policy: (yok)",
                    solution="Permissions-Policy ekleyin ve sadece gerekli API'lere izin verin",
                    mini_trick="Örneğin: Permissions-Policy: camera=(), microphone=(), geolocation=(self)",
                    reference="OWASP Permissions Policy",
                    category="header",
                )
            )
            return

        analysis.permissions_policy_present = True

        # Politikaları parse et
        policies = pp_header.split(",")
        for policy in policies:
            policy = policy.strip()
            analysis.permissions_policy_policies.append(policy)

            # Gereksiz izinleri kontrol et
            dangerous_apis = ["camera", "microphone", "geolocation", "payment", "usb"]
            for api in dangerous_apis:
                if f"{api}=" in policy.lower() and "()" not in policy:
                    self.findings.append(
                        Finding(
                            title=f"Permissions-Policy: {api} API'ine İzin Veriliyor",
                            severity="Sarı",
                            score_impact=-1,
                            description=f"{api} API'si açık, bu potansiyel gizlilik riski.",
                            evidence=f"Permissions-Policy: {policy}",
                            solution=f"{api} için Permissions-Policy'de kısıtlama yapın",
                            mini_trick=f"{api}=() ile tamamen kapatabilirsiniz",
                            reference="OWASP Permissions Policy",
                            category="header",
                        )
                    )

    def _analyze_cross_origin_policies(self, headers: dict, analysis: HeaderAnalysis):
        """Cross-Origin başlıklarını analiz et"""
        if headers.get("cross-origin-opener-policy"):
            analysis.cross_origin_opener_policy_present = True

        if headers.get("cross-origin-embedder-policy"):
            analysis.cross_origin_embedder_policy_present = True

        if headers.get("cross-origin-resource-policy"):
            analysis.cross_origin_resource_policy_present = True

    def _analyze_cache_control(self, cache_header: str, analysis: HeaderAnalysis):
        """Cache-Control analizi"""
        if cache_header:
            analysis.cache_control_present = True
            analysis.cache_control_value = cache_header

    def _analyze_server_headers(self, headers: dict, analysis: HeaderAnalysis):
        """Server ve X-Powered-By başlıklarını analiz et (bilgi sızdırma)"""
        server = headers.get("server")
        if server:
            analysis.server_header = server

            # Versiyon bilgisi sızıntısı kontrolü
            version_pattern = r"\d+\.\d+\.?\d*"
            if re.search(version_pattern, server):
                self.findings.append(
                    Finding(
                        title="Server Header'da Versiyon Bilgisi Sızdırılıyor",
                        severity="Sarı",
                        score_impact=-2,
                        description=f"Server header'da açık versiyon bilgisi var: {server}",
                        evidence=f"Server: {server}",
                        solution="1. Sunucu konfigürasyonunda server header'ı kaldırın veya değiştirin\n2. Reverse proxy kullanın",
                        mini_trick="Nginx için: server_tokens off; Apache için: ServerSignature Off",
                        reference="OWASP Information Disclosure",
                        category="header",
                    )
                )

        x_powered_by = headers.get("x-powered-by")
        if x_powered_by:
            analysis.x_powered_by = x_powered_by

            self.findings.append(
                Finding(
                    title="X-Powered-By Header Bilgi Sızdırıyor",
                    severity="Sarı",
                    score_impact=-1,
                    description=f"X-Powered-By header'da framework bilgisi sızdırılıyor: {x_powered_by}",
                    evidence=f"X-Powered-By: {x_powered_by}",
                    solution="X-Powered-By header'ını kaldırın",
                    mini_trick="PHP için: expose_php = Off; Node.js için: app.disable('x-powered-by')",
                    reference="OWASP Information Disclosure",
                    category="header",
                )
            )

    def _analyze_cors(self, headers: dict, analysis: HeaderAnalysis):
        """CORS başlıklarını analiz et"""
        origin = headers.get("access-control-allow-origin")
        credentials = headers.get("access-control-allow-credentials")

        if origin:
            analysis.cors_origin = origin
            if credentials and credentials.lower() == "true":
                analysis.cors_credentials = True

                # Wildcard + credentials = DANGEROUS
                if origin == "*":
                    self.findings.append(
                        Finding(
                            title="Tehlikeli CORS Konfigürasyonu: Wildcard + Credentials",
                            severity="Kırmızı",
                            score_impact=-15,
                            description="CORS'ta wildcard (*) ile birlikte credentials kullanılıyor. Bu güvenlik açığıdır!",
                            evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                            solution="1. Wildcard yerine spesifik domain kullanın\n2. Credentials gerekiyorsa wildcard KULLANMAYIN",
                            mini_trick="credentials: true kullanıyorsanız, origin mutlaka spesifik domain olmalı",
                            reference="OWASP CORS",
                            category="header",
                        )
                    )
                elif "localhost" in origin.lower() or "127.0.0.1" in origin:
                    self.findings.append(
                        Finding(
                            title="CORS'ta Localhost İzin Veriliyor",
                            severity="Sarı",
                            score_impact=-3,
                            description="CORS'ta localhost veya 127.0.0.1'e izin veriliyor. Production için riskli.",
                            evidence=f"Access-Control-Allow-Origin: {origin}",
                            solution="Production'da localhost'a izin vermeyin",
                            mini_trick="Geliştirme ve production için farklı CORS konfigürasyonları kullanın",
                            reference="OWASP CORS",
                            category="header",
                        )
                    )
