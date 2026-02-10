# 🔒 Web-Scan

<div align="center">

**Yasal ve Etik Pasif Web Güvenlik Tarama Aracı**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-passive-brightgreen.svg)]()
[![Used in AltaySec Atölye](https://img.shields.io/badge/Used%20in-AltaySec%20Atolye-b91c1c?style=flat-square)](https://atolye.altaysec.com.tr)


</div>

## 🔗 Referans & Kullanım

Bu proje, **AltaySec Atölye** platformunda eğitim ve güvenlik farkındalığı amacıyla kullanılmaktadır.

- **AltaySec Atölye:** https://atolye.altaysec.com.tr  
- **AltaySec Ana Site:** https://altaysec.com.tr


## ✨ Özellikler

- 🎯 **0-100 Güvenlik Skoru**: Kırmızı, Sarı, Yeşil etiketleriyle
- 🔍 **Pasif Tarama**: Aktif saldırı yok, yasal ve etik
- 📋 **HTTP Header Analizi**: CSP, HSTS, X-Frame-Options, CORS vb.
- 🍪 **Cookie Güvenliği**: Secure, HttpOnly, SameSite
- 🔒 **HTTPS/TLS Analizi**: Sertifika kontrolü
- 🌐 **DNS Güvenliği**: SPF, DKIM, DMARC, CAA
- 📄 **Sayfa Yapısı**: Form, iframe, mixed content
- 📊 **3 Farklı Rapor**: Terminal, JSON, Markdown
- 🦈 **Shark Mode**: Daha katı puanlama
- 🇹🇷 **Tamamen Türkçe**: Açıklamalar ve çözümler
- ⚡ **Hızlı Kazanımlar**: Önce bunları düzelt

## 🚀 Kurulum

```bash
# Klonlayın
git clone https://github.com/koray-yolcu-sec/web-scan.git
cd web-scan

# Bağımlılıkları yükleyin
pip install -e .
```

## 📖 Kullanım

### Basit Tarama

```bash
web-scan scan https://example.com
```

### Detaylı Tarama

```bash
web-scan scan https://example.com \
  --output report.md \
  --json report.json \
  --max-requests 20 \
  --timeout 10
```

### Shark Mode (Daha Katı Puanlama)

```bash
web-scan scan https://example.com --shark-mode
```

### Login Path'lerini Kapatma

```bash
web-scan scan https://example.com --no-login-paths
```

## 📊 Örnek Çıktı

```
🎯 Güvenlik Skoru: 76/100 (Sarı)

Bu skor ne anlama geliyor?
Site genel olarak güvenli görünüyor ama önemli iyileştirmeler gerekli.

🎯 Önce Bunları Düzelt
1. Content-Security-Policy (CSP) Eksik (-10)
2. Strict-Transport-Security (HSTS) Eksik (-10)
3. X-Frame-Options veya frame-ancestors Eksik (-8)
4. Mixed Content Tespit Edildi (-8)
5. Session Cookie Secure Flag Eksik (-5)

⚡ Hızlı Kazanımlar (Quick Wins)
1. X-Content-Type-Options: nosniff Eksik (-5)
2. Referrer-Policy Eksik (-4)
3. Session Cookie SameSite Eksik veya Gevşek (-3)
4. Permissions-Policy Eksik (-3)
5. Permissions-Policy: camera API'sine İzin Veriliyor (-1)
```

## 🎯 Skorlama Sistemi

### Başlangıç
- Başlangıç puanı: 100

### Kritik Eksikler
- HTTPS yoksa: **-35**
- CORS wildcard + credentials: **-15**
- HSTS yoksa: **-10**
- CSP yoksa veya zayıfsa: **-10**
- X-Frame-Options yoksa: **-8**

### Cookie Güvenliği
- Session cookie Secure eksik: **-5**
- Session cookie HttpOnly eksik: **-4**
- Session cookie SameSite eksik: **-3**

### Diğer Header'lar
- X-Content-Type-Options yoksa: **-5**
- Referrer-Policy yoksa: **-4**
- Permissions-Policy yoksa: **-3**

### Renk Eşikleri
- **0-49**: 🔴 Kırmızı - Düşük güvenlik
- **50-79**: 🟡 Sarı - Orta güvenlik
- **80-100**: 🟢 Yeşil - İyi güvenlik

Daha fazla bilgi için: [docs/scoring.md](docs/scoring.md)

## ⚖️ Yasal ve Etik Sınırlar

### ✅ Bu Tool Ne Yapar
- Pasif HTTP/HTTPS analiz
- Header ve cookie kontrol
- DNS güvenlik kayıtları
- HTTPS/TLS sertifika kontrol
- Sayfa yapısı ve frontend güvenlik sinyalleri
- Yasal ve etik sınırlar içinde kalır

### ❌ Bu Tool Ne YAPMAZ
- Aktif saldırı veya exploit denemeleri
- Brute-force veya credential stuffing
- SQLi, XSS gibi istismar testleri
- Agresif tarama veya rate limit zorlama
- Gizli dizin brute-force (yoğun)

## 📋 Komut Satırı Seçenekleri

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `--output`, `-o` | Markdown rapor çıktı dosyası | - |
| `--json` | JSON rapor çıktı dosyası | - |
| `--max-requests` | Maksimum istek sayısı | 15 |
| `--timeout` | Zaman aşımı (saniye) | 10 |
| `--no-polite` | Polite mode'u kapat | False |
| `--shark-mode` | Shark Mode (daha katı) | False |
| `--paths` | Kontrol edilecek path'ler | Otomatik |
| `--no-login-paths` | /login ve /admin kontrol etme | False |

## 🛠️ Quick Fix Checklist

### Nginx
```nginx
# HTTPS redirect
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self';" always;
```

### Apache
```apache
# HTTPS redirect
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

# Security headers
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

### Cloudflare
- Cloudflare'da bu header'lar otomatik olarak eklenir
- Transform Rules > Modify Response Header ile ekleyebilirsiniz
- Page Rules ile HTTPS zorlama yapabilirsiniz

## 📚 Dokümantasyon

- [Architecture](docs/architecture.md) - Mimari ve tasarım
- [Scoring](docs/scoring.md) - Skorlama modeli
- [Legal & Ethical](docs/legal-ethical.md) - Yasal ve etik sınırlar
- [Limitations](docs/limitations.md) - Sınırlamalar
- [Usage](docs/usage.md) - Detaylı kullanım kılavuzu

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. [LICENSE](LICENSE) dosyasına bakın.

## ⚠️ Yasal Uyarı

Bu araç **sadece** sahip olduğunuz veya açıkça test izni aldığınız sistemler üzerinde kullanılmak üzere tasarlanmıştır. Herhangi bir izin olmadan başkasına ait sistemlerde tarama yapmak yas dışıdır ve suç teşkil eder.

## 🙏 Teşekkürler

- [OWASP](https://owasp.org/) - Güvenlik standartları ve referanslar
- Python topluluğu - Harika kütüphaneler ve araçlar

## 📞 İletişim

- GitHub Issues: [github.com/koray-yolcu-sec/web-scan/issues](https://github.com/koray-yolcu-sec/web-scan/issues)

---

<div align="center">

**Güvenli internet için güvenli yazılım 🔒**

Made with ❤️ by Koray Yolcu

</div>
