"""
HeaderAnalyzer testleri
"""
import pytest
from src.trscan.analyzers import HeaderAnalyzer


def test_csp_missing():
    """CSP eksik testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {}  # CSP yok
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.csp_present == False
    assert len(findings) > 0
    assert any("CSP" in f.title for f in findings)
    assert any(f.severity == "Kırmızı" for f in findings if "CSP" in f.title)


def test_csp_present_basic():
    """Temel CSP var testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'content-security-policy': "default-src 'self'; script-src 'self'"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.csp_present == True
    assert analysis.csp_has_default_src == True
    assert analysis.csp_has_unsafe_inline == False


def test_csp_with_unsafe_inline():
    """CSP unsafe-inline testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.csp_present == True
    assert analysis.csp_has_unsafe_inline == True
    assert analysis.csp_quality_score < 100


def test_hsts_missing():
    """HSTS eksik testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {}  # HSTS yok
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.hsts_present == False
    assert any("HSTS" in f.title for f in findings)


def test_hsts_present_good():
    """İyi HSTS konfigürasyonu testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'strict-transport-security': "max-age=31536000; includeSubDomains; preload"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.hsts_present == True
    assert analysis.hsts_max_age == 31536000
    assert analysis.hsts_include_subdomains == True
    assert analysis.hsts_preload == True


def test_hsts_weak():
    """Zayıf HSTS konfigürasyonu testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'strict-transport-security': "max-age=300"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.hsts_present == True
    assert analysis.hsts_max_age == 300
    assert analysis.hsts_include_subdomains == False
    # Zayıf konfigürasyon için bulgu olmalı
    assert any("HSTS" in f.title and "iyileştirilebilir" in f.title.lower() for f in findings)


def test_x_frame_options_missing():
    """X-Frame-Options eksik testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {}  # XFO yok
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_frame_options_present == False
    assert any("X-Frame-Options" in f.title for f in findings)


def test_x_frame_options_present():
    """X-Frame-Options var testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'x-frame-options': "SAMEORIGIN"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_frame_options_present == True
    assert analysis.x_frame_options_value == "SAMEORIGIN"


def test_x_frame_options_dangerous():
    """Tehlikeli X-Frame-Options testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'x-frame-options': "ALLOWALL"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_frame_options_present == True
    assert analysis.x_frame_options_value == "ALLOWALL"
    assert any("ALLOWALL" in f.title for f in findings)


def test_x_content_type_options_missing():
    """X-Content-Type-Options eksik testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {}  # XCTO yok
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_content_type_options_present == False
    assert any("X-Content-Type-Options" in f.title for f in findings)


def test_x_content_type_options_present():
    """X-Content-Type-Options var testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'x-content-type-options': "nosniff"
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_content_type_options_present == True


def test_cors_wildcard_with_credentials():
    """Tehlikeli CORS (wildcard + credentials) testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true'
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.cors_origin == '*'
    assert analysis.cors_credentials == True
    assert any("CORS" in f.title and "Tehlikeli" in f.title for f in findings)


def test_server_version_disclosure():
    """Server header versiyon sızdırma testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'server': 'nginx/1.18.0'
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.server_header == 'nginx/1.18.0'
    assert any("Server" in f.title and "versiyon" in f.title.lower() for f in findings)


def test_x_powered_by_disclosure():
    """X-Powered-By disclosure testi"""
    analyzer = HeaderAnalyzer(shark_mode=False)
    
    headers = {
        'x-powered-by': 'PHP/8.1.0'
    }
    
    analysis, findings = analyzer.analyze(headers)
    
    assert analysis.x_powered_by == 'PHP/8.1.0'
    assert any("X-Powered-By" in f.title for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])