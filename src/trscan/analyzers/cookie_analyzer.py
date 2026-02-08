from typing import Dict, List, Optional, Tuple
from ..models.scan_result import CookieInfo, Finding


class CookieAnalyzer:
    """Cookie güvenlik analizcisi"""
    
    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.findings: List[Finding] = []
    
    def analyze(self, cookies: List[Dict]) -> Tuple[List[CookieInfo], List[Finding]]:
        """
        Cookie'leri analiz eder
        
        Returns:
            (List[CookieInfo], List[Finding])
        """
        cookie_infos = []
        self.findings = []
        
        session_cookie_names = [
            'sessionid', 'session', 'sid', 'phpsessid', 'jsessionid', 
            'aspsessionid', 'user_session', 'auth_token', 'token'
        ]
        
        for cookie in cookies:
            cookie_info = CookieInfo(
                name=cookie['name'],
                value=cookie['value'],
                domain=cookie['domain'],
                path=cookie['path'],
                secure=cookie['secure'],
                httponly=cookie['httponly'],
                samesite=cookie['samesite'],
                max_age=cookie['max_age'],
                is_session=self._is_session_cookie(cookie['name'], cookie['max_age'], session_cookie_names),
                is_third_party=self._is_third_party_cookie(cookie)
            )
            
            cookie_infos.append(cookie_info)
            
            # Cookie güvenlik analizleri
            self._analyze_cookie_security(cookie_info)
        
        # Genel cookie bulguları
        if not cookie_infos:
            self.findings.append(Finding(
                title="Cookie Set Edilmedi",
                severity="Yeşil",
                score_impact=0,
                description="Site cookie set etmiyor. Bu normal olabilir.",
                evidence="Set-Cookie header: (yok)",
                solution="Cookie kullanıyorsanız güvenlik flag'lerini kontrol edin",
                mini_trick="Session yönetimi için cookie kullanıyorsanız Secure/HttpOnly/SameSite ekleyin",
                reference="OWASP Cookie Security",
                category="cookie"
            ))
        
        return cookie_infos, self.findings
    
    def _analyze_cookie_security(self, cookie: CookieInfo):
        """Tekil cookie güvenlik analizleri"""
        
        # Session cookie'de Secure flag eksik
        if cookie.is_session and not cookie.secure:
            self.findings.append(Finding(
                title=f"Session Cookie Secure Flag Eksik: {cookie.name}",
                severity="Kırmızı",
                score_impact=-5,
                description=f"Session cookie '{cookie.name}' Secure flag içermiyor. HTTP üzerinden çalınabilir.",
                evidence=f"Set-Cookie: {cookie.name}; (Secure yok)",
                solution="1. Cookie'ye Secure flag ekleyin\n2. Sadece HTTPS kullanın",
                mini_trick="Secure flag, cookie'nin sadece HTTPS üzerinden iletilmesini sağlar",
                reference="OWASP Cookie Security",
                category="cookie"
            ))
        
        # Session cookie'de HttpOnly flag eksik
        if cookie.is_session and not cookie.httponly:
            self.findings.append(Finding(
                title=f"Session Cookie HttpOnly Flag Eksik: {cookie.name}",
                severity="Kırmızı",
                score_impact=-4,
                description=f"Session cookie '{cookie.name}' HttpOnly flag içermiyor. XSS ile çalınabilir.",
                evidence=f"Set-Cookie: {cookie.name}; (HttpOnly yok)",
                solution="1. Cookie'ye HttpOnly flag ekleyin\n2. JavaScript'ten cookie erişimini engeller",
                mini_trick="HttpOnly, document.cookie ile erişimi engeller, XSS riskini azaltır",
                reference="OWASP Cookie Security",
                category="cookie"
            ))
        
        # SameSite eksik veya gevşek
        if cookie.is_session:
            if not cookie.samesite or cookie.samesite.lower() == 'none':
                severity = "Sarı" if cookie.samesite else "Kırmızı"
                impact = -3 if not cookie.samesite else -2
                
                self.findings.append(Finding(
                    title=f"Session Cookie SameSite Eksik veya Gevşek: {cookie.name}",
                    severity=severity,
                    score_impact=impact,
                    description=f"Session cookie '{cookie.name}' SameSite flag eksik veya None. CSRF riski.",
                    evidence=f"Set-Cookie: {cookie.name}; SameSite={cookie.samesite or 'yok'}",
                    solution="1. SameSite=Strict veya Lax kullanın\n2. Cross-site request'i engeller",
                    mini_trick="SameSite=Lax çoğu durum için yeterli, Strict daha agresif",
                    reference="OWASP SameSite",
                    category="cookie"
                ))
        
        # Uzun max-age (kalıcı session)
        if cookie.max_age and cookie.max_age > 86400 * 30:  # 30 günden fazla
            self.findings.append(Finding(
                title=f"Cookie Çok Uzun Süre Geçerli: {cookie.name}",
                severity="Sarı",
                score_impact=-1,
                description=f"Cookie '{cookie.name}' {cookie.max_age / 86400:.0f} gün geçerli. Kritik cookie için çok uzun.",
                evidence=f"Set-Cookie: {cookie.name}; Max-Age={cookie.max_age}",
                solution="1. Session cookie için kısa süre (örn. 1-2 saat) kullanın\n2. Remember-me cookie için daha uzun olabilir",
                mini_trick="Kritik cookie'ler için max-age yok (session cookie) veya kısa süre kullanın",
                reference="OWASP Session Management",
                category="cookie"
            ))
    
    def _is_session_cookie(self, name: str, max_age: Optional[int], session_names: List[str]) -> bool:
        """Cookie'nin session cookie olup olmadığını kontrol et"""
        name_lower = name.lower()
        
        # İsim kontrolü
        if any(session_name in name_lower for session_name in session_names):
            return True
        
        # max-age kontrolü (0 veya yoksa session cookie)
        if max_age is None or max_age == 0:
            return True
        
        return False
    
    def _is_third_party_cookie(self, cookie: Dict) -> bool:
        """Cookie'nin third-party olup olmadığını kontrol et"""
        # Domain bilgisi kontrol edilerek yapılabilir
        # Basit kontrol için False döndür
        return False