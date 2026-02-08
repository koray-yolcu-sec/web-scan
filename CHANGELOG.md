# Changelog

Tüm bu projedeki önemli değişiklikler bu dosyada kayıt altına alınacaktır.

Bu projenin formatı, [Keep a Changelog](https://keepachangelog.com/tr-TR/1.0.0/)
tabanlıdır ve proje sürüm numaraları [Semantic Versioning](https://semver.org/lang/tr-TR/)
üzerine kurulmuştur.

## [Unreleased]

### Eklenecek
- Daha fazla TLS analiz özelliği
- PDF rapor export seçeneği
- Web UI arayüzü

## [1.0.0] - 2024-01-XX

### Eklendi
- 🎉 İlk sürüm!
- Pasif web güvenlik tarama motoru
- 100 üzerinden güvenlik skoru sistemi
- HTTP header güvenlik analizi (CSP, HSTS, X-Frame-Options vb.)
- Cookie güvenlik analizi (Secure, HttpOnly, SameSite)
- HTTPS/TLS sertifikası analizi
- DNS güvenlik analizi (SPF, DKIM, DMARC, CAA)
- Bilgi sızdırma tespiti (Server header, X-Powered-By vb.)
- Robots.txt, sitemap.xml, security.txt analizi
- Sayfa yapısı analizi (form, iframe, mixed content)
- CORS güvenlik analizi
- Hafif path kontrolleri (/login, /admin vb.)
- 3 farklı rapor formatı: Terminal, JSON, Markdown
- "Shark Mode 🦈" (daha katı puanlama)
- "Quick Fix Checklist" (nginx/apache/cloudflare için)
- Tamamen Türkçe çıktı ve açıklamalar
- CLI arayüzü (--output, --json, --max-requests, --timeout, --polite)
- Önceliklendirilmiş bulgu listesi
- "Quick Wins" ve "Ne Anlama Geliyor?" bölümleri

### Özellikler
- Asenkron HTTP client (httpx)
- Rate limiting ve "polite mode"
- Zaman aşımı (timeout) koruması
- Hata yönetimi ve Türkçe hata mesajları
- OWASP referansları
- GitHub Actions CI/CD pipeline

### Dokümantasyon
- README.md (Türkçe ve İngilizce özet)
- docs/architecture.md
- docs/scoring.md
- docs/legal-ethical.md
- docs/limitations.md
- docs/usage.md
- CONTRIBUTING.md
- MIT License
- Yasal ve etik uyarılar

[Unreleased]: https://github.com/web-scan/web-scan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/web-scan/web-scan/releases/tag/v1.0.0