# Kullanım Kılavuzu

Bu doküman, Web-Scan aracının detaylı kullanımını açıklar.

## 🚀 Hızlı Başlangıç

### Kurulum

```bash
# Repo'yu klonlayın
git clone https://github.com/koray-yolcu-sec/web-scan.git
cd web-scan

# Bağımlılıkları yükleyin
pip install -e .

# Kurulumu doğrulayın
web-scan --version
```

### İlk Tarama

```bash
# Basit tarama
web-scan scan https://example.com
```

Bu komut:
1. Siteyi tarar
2. Güvenlik skorunu hesaplar
3. Terminal raporu gösterir

## 📋 Komut Satırı Seçenekleri

### Temel Seçenekler

| Seçenek | Kısa | Açıklama | Varsayılan |
|---------|------|----------|------------|
| `--output` | `-o` | Markdown rapor çıktı dosyası | - |
| `--json` | - | JSON rapor çıktı dosyası | - |
| `--max-requests` | - | Maksimum istek sayısı | 15 |
| `--timeout` | - | Zaman aşımı (saniye) | 10 |
| `--no-polite` | - | Polite mode'u kapat | False |
| `--shark-mode` | - | Shark Mode (daha katı) | False |
| `--paths` | - | Kontrol edilecek path'ler | Otomatik |
| `--no-login-paths` | - | /login ve /admin kontrol etme | False |

### Detaylı Açıklamalar

#### `--output`, `-o`

Markdown raporu belirtilen dosyaya kaydeder.

```bash
web-scan scan https://example.com --output report.md
```

**Çıktı**: `report.md` dosyasına güzel formatlanmış rapor.

#### `--json`

JSON raporu belirtilen dosyaya kaydeder.

```bash
web-scan scan https://example.com --json report.json
```

**Çıktı**: `report.json` dosyasına otomasyon için uygun JSON.

**Her ikisini bir arada kullanabilirsiniz**:

```bash
web-scan scan https://example.com --output report.md --json report.json
```

#### `--max-requests`

Maksimum HTTP istek sayısını belirler.

```bash
web-scan scan https://example.com --max-requests 20
```

**Not**: Daha fazla istek = daha detaylı tarama ama daha yavaş.

#### `--timeout`

Zaman aşımı süresini saniye cinsinden belirler.

```bash
web-scan scan https://example.com --timeout 15
```

**Not**: Yavaş siteler için artırabilirsiniz.

#### `--no-polite`

Polite mode'u kapatır (yapmamanızı öneririz).

```bash
web-scan scan https://example.com --no-polite
```

**Not**: Bu sunucuyu yorabilir, production için kullanmayın.

#### `--shark-mode`

Shark Mode aktif eder (%30 daha katı puanlama).

```bash
web-scan scan https://example.com --shark-mode
```

**Ne değişir?**
- Tüm negatif etkiler %30 daha fazla kırılır
- Daha katı standartlar uygulanır
- Production için önerilir

#### `--paths`

Kontrol edilecek path'leri manuel belirtir.

```bash
web-scan scan https://example.com --paths /robots.txt /sitemap.xml /api
```

**Not**: Varsayılan path'leri override eder.

#### `--no-login-paths`

/login ve /admin path kontrollerini kapatır.

```bash
web-scan scan https://example.com --no-login-paths
```

**Not**: Bu path'leri kontrol etmek istemiyorsanız kullanın.

## 🎯 Kullanım Senaryoları

### Senaryo 1: Basit Tarama

**Senaryo**: Sitenizi hızlıca kontrol etmek istiyorsunuz.

```bash
web-scan scan https://example.com
```

**Ne yapar?**
- Varsayılan path'leri kontrol eder
- Terminal raporu gösterir
- Dosyaya kaydetmez

### Senaryo 2: Detaylı Tarama

**Senaryo**: Sitenizi detaylı analiz etmek istiyorsunuz.

```bash
web-scan scan https://example.com \
  --output report.md \
  --json report.json \
  --max-requests 20 \
  --timeout 15
```

**Ne yapar?**
- Daha fazla path kontrol eder
- Timeout'u artırır
- Hem Markdown hem JSON rapor kaydeder

### Senaryo 3: Production Tarama

**Senaryo**: Production sitenizi shark mode ile taramak istiyorsunuz.

```bash
web-scan scan https://example.com \
  --shark-mode \
  --output production_report.md \
  --max-requests 25
```

**Ne yapar?**
- Shark mode aktif eder (daha katı)
- Production için uygundur
- Detaylı rapor kaydeder

### Senaryo 4: Test Ortamı Tarama

**Senaryo**: Test ortamınızı hızlıca kontrol etmek istiyorsunuz.

```bash
web-scan scan https://test.example.com \
  --max-requests 10 \
  --timeout 5
```

**Ne yapar?**
- Daha az istek yapar (hızlı)
- Kısa timeout
- Test ortamı için ideal

### Senaryo 5: Özel Path Tarama

**Senaryo**: Sadece belirli path'leri kontrol etmek istiyorsunuz.

```bash
web-scan scan https://example.com \
  --paths /robots.txt /sitemap.xml /api/v1/health
```

**Ne yapar?**
- Belirtilen path'leri kontrol eder
- /login ve /admin kontrol etmez
- Özel API endpoint test

### Senaryo 6: Login Path'lerini Atla

**Senaryo**: /login ve /admin path'lerini kontrol etmek istemiyorsunuz.

```bash
web-scan scan https://example.com \
  --no-login-paths \
  --output report.md
```

**Ne yapar?**
- /login ve /admin kontrol etmez
- Diğer path'leri kontrol eder
- Rapor kaydeder

## 📊 Çıktı Formatları

### Terminal Çıktısı

Terminal çıktısı renkli ve okunabilir:

```
======================================================================
🔒 TR-Pasif Web Güvenlik Skoru v1.0.0
Yasal ve etik pasif web güvenlik tarama aracı
======================================================================

[🌐] Ana sayfa çekiliyor: https://example.com
[✅] Ana sayfa çekildi (Status: 200)
[🍪] Cookie'ler analiz ediliyor...
[✅] 3 cookie analiz edildi
[📋] Header'lar analiz ediliyor...
[✅] Header'lar analiz edildi
[🔒] TLS/HTTPS analiz ediliyor...
[✅] TLS/HTTPS analiz edildi
[📄] Sayfa yapısı analiz ediliyor...
[✅] Sayfa yapısı analiz edildi
[🔍] 5 path kontrol ediliyor...
[✅] Path'ler kontrol edildi
[🌐] DNS güvenlik kayıtları analiz ediliyor...
[✅] DNS kayıtları analiz edildi
[💯] Güvenlik skoru hesaplanıyor...
[✅] Skor hesaplandı: 76/100 (Sarı)

======================================================================
✅ Tarama Tamamlandı!
======================================================================

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 💯 Skor                                                     ┃
┃                                                            ┃
┃ Güvenlik Skoru: 76/100                                     ┃
┃ (Sarı - Orta)                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

🎯 Önce Bunları Düzelt
┏━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ Öncelik                                                   ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ Content-Security-Policy (CSP) Eksik                     │
│ 2 │ Strict-Transport-Security (HSTS) Eksik                   │
│ 3 │ X-Frame-Options veya frame-ancestors Eksik              │
└───┴──────────────────────────────────────────────────────────┘
...
```

### Markdown Raporu

Markdown raporu GitHub'da paylaşılabilecek format:

```markdown
# 🔒 TR-Pasif Web Güvenlik Skoru Raporu

**Hedef:** https://example.com
**Tarih:** 2024-01-15 10:30:45
Süre: 5.23 saniye

## 💯 Güvenlik Skoru

🟡 **76/100** (Sarı - Orta)

### 💡 Bu Skor Ne Anlama Geliyor?
Site genel olarak güvenli görünüyor ama önemli iyileştirmeler gerekli.

## 🎯 Önce Bunları Düzelt

1. Content-Security-Policy (CSP) Eksik
2. Strict-Transport-Security (HSTS) Eksik
3. X-Frame-Options veya frame-ancestors Eksik

## ⚡ Hızlı Kazanımlar (Quick Wins)

1. X-Content-Type-Options: nosniff Eksik (-5)
2. Referrer-Policy Eksik (-4)
3. Session Cookie SameSite Eksik veya Gevşek (-3)
...
```

### JSON Raporu

JSON raporu otomasyon için uygun:

```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "scan_date": "2024-01-15T10:30:45",
    "scan_duration_seconds": 5.23,
    "shark_mode": false,
    "max_requests": 15,
    "timeout": 10
  },
  "score": {
    "score": 76,
    "color": "Sarı",
    "label": "Orta",
    "meaning": "Site genel olarak güvenli görünüyor ama önemli iyileştirmeler gerekli."
  },
  "summary": {
    "quick_wins": [
      "X-Content-Type-Options: nosniff Eksik (-5)",
      "Referrer-Policy Eksik (-4)",
      ...
    ],
    "top_priorities": [
      "Content-Security-Policy (CSP) Eksik (header)",
      ...
    ],
    "categories_summary": {
      "Kritik": 0,
      "Yüksek": 3,
      "Orta": 5,
      "Düşük": 2,
      "Bilgi": 0
    }
  },
  "findings": [
    {
      "title": "Content-Security-Policy (CSP) Eksik",
      "severity": "Kırmızı",
      "score_impact": -10,
      "description": "Site, Content-Security-Policy başlığı içermiyor...",
      "evidence": "Content-Security-Policy: (yok)",
      "solution": "1. Sunucu konfigürasyonuna CSP header ekleyin...",
      "mini_trick": "Emin değilseniz, önce 'Report-Only' modunda test edin...",
      "reference": "OWASP Content Security Policy",
      "category": "header"
    },
    ...
  ]
}
```

## 🛠️ Gelişmiş Kullanım

### Batch Tarama

Birden fazla siteyi taramak için script:

```bash
#!/bin/bash

# sites.txt dosyasına sitelerinizi ekleyin
# https://example1.com
# https://example2.com
# https://example3.com

while read -r url; do
    echo "Taranıyor: $url"
    web-scan scan "$url" --output "reports/$(basename $url).md" --json "reports/$(basename $url).json"
    echo "Tamamlandı: $url"
    echo "---"
done < sites.txt
```

Kullanım:
```bash
chmod +x batch_scan.sh
./batch_scan.sh
```

### CI/CD Entegrasyonu

GitHub Actions ile entegrasyon:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.11'
    
    - name: Install TRScan
      run: |
        git clone https://github.com/web-scan/web-scan.git
        cd web-scan
        pip install -e .
    
    - name: Scan Website
      run: |
        web-scan scan https://example.com --output report.md --json report.json
    
    - name: Upload Reports
      uses: actions/upload-artifact@v2
      with:
        name: security-reports
        path: |
          report.md
          report.json
```

### Python API Kullanımı

Python kodundan kullanma:

```python
import asyncio
from web-scan import WebSecurityScanner

async def scan_site():
    # Scanner oluştur
    scanner = WebSecurityScanner(
        shark_mode=True,
        max_requests=20,
        timeout=10,
    )
    
    # Tara
    result = await scanner.scan("https://example.com")
    
    # Skor
    print(f"Skor: {result.score.score}/100 ({result.score.color})")
    
    # Bulgular
    for finding in result.findings:
        print(f"- {finding.title}: {finding.severity} ({finding.score_impact})")
    
    # Rapor oluştur
    markdown = scanner.generate_markdown_report(result)
    with open("report.md", "w") as f:
        f.write(markdown)

# Çalıştır
asyncio.run(scan_site())
```

## 📈 Skor İyileştirme Rehberi

### 0-49 (Kırmızı) - Düşük Güvenlik

**Acil Düzeltmeler:**
1. HTTPS ekle (+35)
2. HSTS ekle (+10)
3. CSP ekle (+10)
4. X-Frame-Options ekle (+8)
5. Cookie güvenliği (+12)

**Potansiyel Kazanç: +75 puan**

### 50-79 (Sarı) - Orta Güvenlik

**İyileştirmeler:**
1. Header kalitesini artır
2. Cookie flag'leri ekle
3. DNS kayıtları ekle
4. Mixed content düzelt
5. Bilgi sızdırma önle

**Potansiyel Kazanç: +30 puan**

### 80-100 (Yeşil) - İyi Güvenlik

**İyileştirmeler:**
1. CSP kalitesini artır
2. HSTS max-age artır
3. TLS sertifika yenile
4. Permissions-Policy detaylandır
5. Uç durumları test et

**Potansiyel Kazanç: +10 puan**

## 🚨 Sorun Giderme

### "Hata: URL erişilemedi"

**Neden**: Site down veya firewall engelliyor.

**Çözüm**:
- Site'nin up olduğunu kontrol edin
- Firewall ayarlarını kontrol edin
- Timeout'u artırın: `--timeout 20`

### "DNS resolution hatası"

**Neden**: DNS kaydı yok veya DNS sorunu.

**Çözüm**:
- Domain doğruluğunu kontrol edin
- DNS server'ını kontrol edin
- Public DNS kullanmayı deneyin

### "Certificate doğrulama hatası"

**Neden**: SSL sertifikası sorunlu.

**Çözüm**:
- Sertifika geçerliliğini kontrol edin
- Sertifika zincirini kontrol edin
- Sertifikayı yenileyin

### "Timeout hatası"

**Neden**: Site çok yavaş veya yanıt vermiyor.

**Çözüm**:
- Timeout'u artırın: `--timeout 20`
- Maksimum isteği azaltın: `--max-requests 10`
- Site performansını optimize edin

## 📚 İpuçları ve Püf Noktaları

### 1. Polite Mode Kullanın
```bash
web-scan scan https://example.com --polite
```
Polite mode sunucuları korur.

### 2. Shark Mode Production İçin
```bash
web-scan scan https://example.com --shark-mode
```
Daha katı standartlar.

### 3. Raporları Saklayın
```bash
web-scan scan https://example.com --output "reports/scan_$(date +%Y%m%d).md"
```
Tarih bazlı raporlama.

### 4. JSON ile Otomasyon
```bash
web-scan scan https://example.com --json report.json
# JSON'u parse edin ve işlem yapın
```
CI/CD entegrasyonu için.

### 5. Test Önce Production Sonra
```bash
web-scan scan https://test.example.com
web-scan scan https://example.com --shark-mode
```
Test sonra production.

## 🔗 Referanslar

- [README.md](../README.md) - Ana dokümantasyon
- [Architecture](architecture.md) - Mimari dokümantasyonu
- [Scoring](scoring.md) - Skorlama modeli
- [Legal & Ethical](legal-ethical.md) - Yasal ve etik sınırlar
- [Limitations](limitations.md) - Sınırlamalar

---

**Sorularınız mı var?** [GitHub Issues](https://github.com/web-scan/web-scan/issues) üzerinden sorun.