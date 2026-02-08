from typing import Dict, Optional, Tuple, List
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
from ..models.scan_result import PageInfo, Finding


class PageAnalyzer:
    """Sayfa yapısı ve frontend güvenlik analizcisi"""
    
    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.findings: List[Finding] = []
    
    def analyze(self, html_content: str, base_url: str, headers: Dict) -> Tuple[PageInfo, List[Finding]]:
        """
        Sayfa yapısını analiz eder
        
        Args:
            html_content: HTML içeriği
            base_url: Base URL
            headers: HTTP header'ları
            
        Returns:
            (PageInfo, List[Finding])
        """
        self.findings = []
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        page_info = PageInfo(
            has_forms=False,
            forms_count=0,
            has_autocomplete_disabled=False,
            has_iframes=False,
            iframes_count=0,
            external_scripts_count=0,
            mixed_content_detected=False,
            meta_generator=self._extract_meta_generator(soup),
            server_header=headers.get('server'),
        )
        
        # Form analizi
        self._analyze_forms(soup, page_info)
        
        # Iframe analizi
        self._analyze_iframes(soup, page_info, base_url)
        
        # External script analizi
        self._analyze_external_scripts(soup, page_info, base_url)
        
        # Mixed content analizi
        self._analyze_mixed_content(soup, page_info, base_url)
        
        # Bilgi sızdırma
        self._analyze_information_disclosure(soup, headers)
        
        return page_info, self.findings
    
    def _analyze_forms(self, soup: BeautifulSoup, page_info: PageInfo):
        """Formları analiz et"""
        forms = soup.find_all('form')
        page_info.has_forms = len(forms) > 0
        page_info.forms_count = len(forms)
        
        for i, form in enumerate(forms[:5]):  # İlk 5 formu kontrol et
            # Autocomplete kontrolü
            autocomplete = form.get('autocomplete', '').lower()
            if autocomplete == 'off':
                page_info.has_autocomplete_disabled = True
                self.findings.append(Finding(
                    title=f"Form'da Autocomplete Kapalı (Form #{i+1})",
                    severity="Yeşil",
                    score_impact=0,
                    description=f"Form {i+1}'de autocomplete özelliği kapalı. Bu güvenlik için iyi.",
                    evidence=f"<form autocomplete='off'>",
                    solution="Kullanıcı deneyimi için kritik alanlarda açık bırakın, hassas alanlarda kapalı kalabilir",
                    mini_trick="Login formunda autocomplete='off' genelde tercih edilir",
                    reference="OWASP Form Security",
                    category="page"
                ))
            
            # Method kontrolü
            method = form.get('method', '').lower()
            if method == 'get':
                self.findings.append(Finding(
                    title=f"Form GET Metodu Kullanıyor (Form #{i+1})",
                    severity="Sarı",
                    score_impact=-2,
                    description=f"Form {i+1} GET metodu kullanıyor. Hassas veriler için POST kullanın.",
                    evidence=f"<form method='GET'>",
                    solution="Hassas veriler için POST metodu kullanın",
                    mini_trick="GET = URL'de görünür, POST = request body'de",
                    reference="OWASP Form Security",
                    category="page"
                ))
    
    def _analyze_iframes(self, soup: BeautifulSoup, page_info: PageInfo, base_url: str):
        """Iframe'leri analiz et"""
        iframes = soup.find_all('iframe')
        page_info.has_iframes = len(iframes) > 0
        page_info.iframes_count = len(iframes)
        
        if len(iframes) > 5:
            self.findings.append(Finding(
                title="Çok Fazla Iframe Kullanımı",
                severity="Sarı",
                score_impact=-2,
                description=f"Sayfada {len(iframes)} iframe var. Bu performans ve güvenlik sorunları yaratabilir.",
                evidence=f"Iframe count: {len(iframes)}",
                solution="1. Gereksiz iframe'leri kaldırın\n2. Lazy loading kullanın\n3. frame-ancestors ile kontrol edin",
                mini_trick="Lazy loading: <iframe loading='lazy'>",
                reference="OWASP Clickjacking",
                category="page"
            ))
        
        for iframe in iframes:
            src = iframe.get('src', '')
            if src:
                parsed_src = urlparse(src)
                parsed_base = urlparse(base_url)
                
                # External iframe kontrolü
                if parsed_src.netloc and parsed_src.netloc != parsed_base.netloc:
                    self.findings.append(Finding(
                        title="External Iframe Algılandı",
                        severity="Sarı",
                        score_impact=-1,
                        description=f"Sayfada external iframe kullanılıyor: {src[:100]}...",
                        evidence=f"<iframe src='{src}'>",
                        solution="1. External kaynağa güvenin\n2. sandbox attribute ekleyin\n3. frame-ancestors ile kontrol edin",
                        mini_trick="Sandbox ile iframe yeteneklerini kısıtlayın: <iframe sandbox>",
                        reference="OWASP Clickjacking",
                        category="page"
                    ))
    
    def _analyze_external_scripts(self, soup: BeautifulSoup, page_info: PageInfo, base_url: str):
        """External script'leri analiz et"""
        scripts = soup.find_all('script', src=True)
        external_scripts = []
        
        parsed_base = urlparse(base_url)
        
        for script in scripts:
            src = script.get('src', '')
            if src:
                parsed_src = urlparse(src)
                # External script kontrolü (protocol'ünüz veya farklı domain)
                if parsed_src.netloc and parsed_src.netloc != parsed_base.netloc:
                    external_scripts.append(src)
        
        page_info.external_scripts_count = len(external_scripts)
        
        if len(external_scripts) > 10:
            self.findings.append(Finding(
                title="Çok Fazla External Script",
                severity="Sarı",
                score_impact=-2,
                description=f"Sayfada {len(external_scripts)} external script var. Bu performans ve güvenlik riski.",
                evidence=f"External script count: {len(external_scripts)}",
                solution="1. Gereksiz external script'leri kaldırın\n2. Script'leri kendi sunucunuza taşıyın\n3. CSP ile kısıtlayın",
                mini_trick="Subresource Integrity (SRI) ile script'leri doğrulayın",
                reference="OWASP Content Security Policy",
                category="page"
            ))
        
        # CDN kontrolü
        cdn_domains = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'ajax.googleapis.com', 'unpkg.com']
        cdn_count = sum(1 for script in external_scripts if any(cdn in script for cdn in cdn_domains))
        
        if cdn_count > 0:
            self.findings.append(Finding(
                title=f"CDN Script'leri Kullanılıyor ({cdn_count} adet)",
                severity="Yeşil",
                score_impact=0,
                description=f"Sayfada {cdn_count} CDN script'i kullanılıyor. Bu genelde iyidir.",
                evidence=f"CDN script count: {cdn_count}",
                solution="CDN kullanmak iyidir, SRI ekleyin ve version pin yapın",
                mini_trick="CDN + SRI = Güvenli ve hızlı",
                reference="OWASP CDN Security",
                category="page"
            ))
    
    def _analyze_mixed_content(self, soup: BeautifulSoup, page_info: PageInfo, base_url: str):
        """Mixed content kontrolü"""
        is_https = base_url.startswith('https://')
        
        if not is_https:
            return  # Mixed content sadece HTTPS sayfalarda sorun
        
        mixed_content_resources = []
        
        # HTTP kaynakları ara
        for tag in soup.find_all(['img', 'script', 'link', 'iframe', 'source']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http://'):
                mixed_content_resources.append(src)
        
        page_info.mixed_content_detected = len(mixed_content_resources) > 0
        
        if mixed_content_resources:
            self.findings.append(Finding(
                title=f"Mixed Content Tespit Edildi ({len(mixed_content_resources)} kaynak)",
                severity="Kırmızı",
                score_impact=-8,
                description=f"HTTPS sayfada {len(mixed_content_resources)} HTTP kaynak var. Şifreleme açığı!",
                evidence=f"HTTP resources: {len(mixed_content_resources)} adet",
                solution="1. Tüm kaynakları HTTPS'e geçirin\n2. Protocol-relative URL'ler kullanın (//domain.com)\n3. CSP upgrade-insecure-requests kullanın",
                mini_trick="//cdn.example.com/script.js hem HTTP hem HTTPS çalışır",
                reference="OWASP Mixed Content",
                category="page"
            ))
    
    def _extract_meta_generator(self, soup: BeautifulSoup) -> Optional[str]:
        """Meta generator tag'ini çıkar"""
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            return meta_generator.get('content', '')
        return None
    
    def _analyze_information_disclosure(self, soup: BeautifulSoup, headers: Dict):
        """Bilgi sızdırma analizi"""
        
        # Meta generator
        meta_generator = self._extract_meta_generator(soup)
        if meta_generator:
            # Versiyon bilgisi var mı?
            version_pattern = r'\d+\.\d+\.?\d*'
            if re.search(version_pattern, meta_generator):
                self.findings.append(Finding(
                    title="Meta Generator'da Versiyon Bilgisi",
                    severity="Sarı",
                    score_impact=-1,
                    description=f"Meta generator tag'inde versiyon bilgisi sızdırılıyor: {meta_generator}",
                    evidence=f"<meta name='generator' content='{meta_generator}'>",
                    solution="Meta generator tag'ini kaldırın veya versiyon bilgisini gizleyin",
                    mini_trick="WordPress gibi CMS'lerde version bilgisini gizleyen eklentiler var",
                    reference="OWASP Information Disclosure",
                    category="page"
                ))
        
        # HTML yorumlarından hassas bilgi kontrolü (basit)
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        sensitive_keywords = ['password', 'api_key', 'secret', 'token', 'todo', 'fixme', 'hack']
        
        for comment in comments[:20]:  # İlk 20 yorumu kontrol et
            comment_text = comment.lower()
            if any(keyword in comment_text for keyword in sensitive_keywords):
                self.findings.append(Finding(
                    title="HTML Yorumlarında Hassas Bilgi İfadesi",
                    severity="Sarı",
                    score_impact=-2,
                    description="HTML yorumlarında potansiyel hassas bilgi ifadesi bulundu.",
                    evidence=f"Comment: {comment[:200]}...",
                    solution="1. HTML yorumlarını temizleyin\n2. Hassas bilgileri yorumlara eklemeyin\n3. Minification kullanın",
                    mini_trick="Production için HTML minification yapın, yorumları kaldırır",
                    reference="OWASP Information Disclosure",
                    category="page"
                ))
                break  # Sadece bir bulgu ekle
        
        # Server header zaten header_analyzer'da kontrol edildi