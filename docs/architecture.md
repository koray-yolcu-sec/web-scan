# Mimari Dokümantasyonu

Bu doküman TR-Pasif Web Güvenlik Skoru aracının mimari yapısını açıklar.

## 📦 Genel Bakış

TR-Pasif Web Güvenlik Skoru, modüler bir Python uygulamasıdır. Her bileşen tek bir sorumluluğa sahiptir ve birbirinden bağımsız olarak çalışabilir.

## 🏗️ Modüler Yapı

```
web-scan/
├── __init__.py                 # Ana paket
├── cli.py                      # CLI arayüzü
├── scanner.py                  # Ana tarayıcı (koordinatör)
├── models/                     # Veri modelleri (Pydantic)
│   ├── __init__.py
│   └── scan_result.py
├── fetcher/                    # Veri toplama
│   ├── __init__.py
│   ├── http_fetcher.py         # HTTP istekleri
│   └── dns_fetcher.py          # DNS sorguları
├── analyzers/                  # Güvenlik analizi
│   ├── __init__.py
│   ├── header_analyzer.py      # Header analizi
│   ├── cookie_analyzer.py      # Cookie analizi
│   ├── tls_analyzer.py         # TLS analizi
│   ├── dns_analyzer.py         # DNS analizi
│   └── page_analyzer.py        # Sayfa analizi
├── scorer/                     # Skorlama
│   ├── __init__.py
│   └── security_scorer.py      # Skor hesaplayıcı
└── reporter/                   # Raporlama
    ├── __init__.py
    └── security_reporter.py    # Rapor oluşturucu
```

## 🔄 Veri Akışı

```
1. CLI Input
   ↓
2. WebSecurityScanner (Koordinatör)
   ↓
3. HTTPFetcher (Ana sayfa + ek path'ler)
   ↓
4. DNSFetcher (DNS kayıtları)
   ↓
5. Analyzers (Header, Cookie, TLS, DNS, Page)
   ↓
6. SecurityScorer (Skor hesapla)
   ↓
7. SecurityReporter (Rapor oluştur)
   ↓
8. Output (Terminal, JSON, Markdown)
```

## 🧩 Bileşen Detayları

### 1. WebSecurityScanner (Koordinatör)

Ana tarayıcı ve koordinatördür. Tüm bileşenleri yönetir ve koordine eder.

**Sorumluluklar:**
- URL normalizasyonu
- Tarama sürecini yönetme
- Bileşenleri sırayla çağırma
- Sonuçları birleştirme

**Metodlar:**
- `scan(target_url)`: Ana tarama metodu
- `_normalize_url(url)`: URL normalizasyonu

### 2. HTTPFetcher

HTTP/HTTPS isteklerini yapar ve verileri toplar.

**Sorumluluklar:**
- Ana sayfa çekme
- Ek path'leri kontrol etme (/robots.txt, /sitemap.xml vb.)
- Header ve cookie toplama
- Redirect zinciri izleme
- Polite mode (rate limiting)

**Metodlar:**
- `fetch_main_page(url)`: Ana sayfa çeker
- `fetch_additional_paths(base_url, paths)`: Ek path'leri kontrol eder
- `_extract_cookies(headers)`: Cookie'leri çıkarır
- `_mask_value(value)`: Cookie değerlerini maskele

### 3. DNSFetcher

DNS güvenlik kayıtlarını çeker.

**Sorumluluklar:**
- SPF kaydı sorgulama
- DKIM kaydı sorgulama
- DMARC kaydı sorgulama
- CAA kaydı sorgulama
- MX kaydı sorgulama

**Metodlar:**
- `fetch_all_records(domain)`: Tüm güvenlik kayıtlarını çeker
- `_query_txt(domain, record_type)`: TXT kaydı sorgular
- `_query_mx(domain)`: MX kaydı sorgular
- `_query_caa(domain)`: CAA kaydı sorgular
- `parse_dmarc_policy(dmarc_records)`: DMARC policy'yi parse eder

### 4. HeaderAnalyzer

HTTP header güvenlik analizcisi.

**Sorumluluklar:**
- CSP analizi (varlık ve kalite)
- HSTS analizi
- X-Frame-Options analizi
- X-Content-Type-Options analizi
- Referrer-Policy analizi
- Permissions-Policy analizi
- Cross-Origin başlıkları analizi
- CORS analizi
- Bilgi sızdırma tespiti

**Metodlar:**
- `analyze(headers)`: Tüm header'ları analiz eder
- `_analyze_csp(csp_header, analysis)`: CSP analiz eder
- `_analyze_hsts(hsts_header, analysis)`: HSTS analiz eder
- `_analyze_x_frame_options(xfo_header, analysis)`: XFO analiz eder
- `_analyze_cors(headers, analysis)`: CORS analiz eder

### 5. CookieAnalyzer

Cookie güvenlik analizcisi.

**Sorumluluklar:**
- Secure flag kontrolü
- HttpOnly flag kontrolü
- SameSite kontrolü
- Session cookie tespiti
- Uzun max-age tespiti

**Metodlar:**
- `analyze(cookies)`: Tüm cookie'leri analiz eder
- `_analyze_cookie_security(cookie)`: Tekil cookie analiz eder
- `_is_session_cookie(name, max_age, session_names)`: Session cookie kontrolü

### 6. TLSAnalyzer

TLS/HTTPS analizcisi.

**Sorumluluklar:**
- HTTPS kontrolü
- HTTP accessible kontrolü
- Sertifika geçerliliği
- Sertifika bitiş tarihi kontrolü
- Mixed content tespiti

**Metodlar:**
- `analyze(fetcher_result)`: TLS durumunu analiz eder
- `_check_certificate_expiry(expiry_date)`: Sertifika bitişini kontrol eder
- `analyze_certificate_details(cert_info)`: Detaylı sertifika analizi

### 7. DNSAnalyzer

DNS güvenlik analizcisi.

**Sorumluluklar:**
- SPF kaydı kontrolü
- DKIM kaydı kontrolü
- DMARC kaydı ve policy kontrolü
- CAA kaydı kontrolü
- Policy kalite analizi

**Metodlar:**
- `analyze(dns_records)`: DNS kayıtlarını analiz eder
- `_parse_dmarc_policy(dmarc_records)`: DMARC policy'yi parse eder

### 8. PageAnalyzer

Sayfa yapısı ve frontend güvenlik analizcisi.

**Sorumluluklar:**
- Form analizi
- Iframe analizi
- External script analizi
- Mixed content analizi
- Bilgi sızdırma tespiti (HTML yorumları, meta generator)

**Metodlar:**
- `analyze(html_content, base_url, headers)`: Sayfa yapısını analiz eder
- `_analyze_forms(soup, page_info)`: Formları analiz eder
- `_analyze_iframes(soup, page_info, base_url)`: Iframe'leri analiz eder
- `_analyze_external_scripts(soup, page_info, base_url)`: External script'leri analiz eder
- `_analyze_mixed_content(soup, page_info, base_url)`: Mixed content kontrolü
- `_analyze_information_disclosure(soup, headers)`: Bilgi sızdırma tespiti

### 9. SecurityScorer

Güvenlik skoru hesaplayıcı.

**Sorumluluklar:**
- 0-100 skor hesaplama
- Renk etiketi belirleme
- Quick wins listesi oluşturma
- Top priorities listesi oluşturma
- Kategori özeti oluşturma
- Shark mode desteği

**Metodlar:**
- `calculate_score(findings, categories, score_impacts)`: Skor hesaplar
- `_get_score_classification(score)`: Skor sınıflandırması
- `_get_quick_wins(findings)`: Hızlı kazanımlar
- `_get_top_priorities(findings)`: Öncelik listesi
- `_get_categories_summary(findings)`: Kategori özeti
- `get_scoring_explanation()`: Skorlama açıklaması

### 10. SecurityReporter

Güvenlik raporu oluşturucu.

**Sorumluluklar:**
- Terminal raporu (rich)
- JSON raporu
- Markdown raporu
- Rapor formatlama ve stil

**Metodlar:**
- `generate_terminal_report(result)`: Terminal raporu
- `generate_json_report(result)`: JSON raporu
- `generate_markdown_report(result)`: Markdown raporu
- `_print_score_panel(result)`: Skor paneli
- `_print_findings(result)`: Bulguları yazdır

## 🎨 Tasarım Prensipleri

### 1. Single Responsibility Principle (SRP)
Her sınıf tek bir sorumluluğa sahiptir. Örneğin, `HeaderAnalyzer` sadece header analizi yapar.

### 2. Open/Closed Principle (OCP)
Sistem açık for extension, kapalı for modification'dır. Yeni analizciler eklenebilir, mevcutlar değiştirilmek zorunda değildir.

### 3. Dependency Inversion Principle (DIP)
Yüksek seviyeli modüller, düşük seviyeli modüllere bağımlıdır, soyutlamalara bağımlıdır.

### 4. Separation of Concerns
Her modül kendi alanında uzmanlaşmıştır:
- **Fetcher**: Veri toplama
- **Analyzer**: Analiz
- **Scorer**: Skorlama
- **Reporter**: Raporlama

## 🔒 Güvenlik Prensipleri

### 1. Passive-First
Tüm analizler pasiftir, aktif saldırı yoktur.

### 2. Rate Limiting
Polite mode ile sunucuları yormaz.

### 3. Privacy
Cookie değerleri maskelenir, hassas bilgiler kaydedilmez.

### 4. Transparency
Tüm kontroller açıkça bildirilir, gizli işlem yoktur.

## 🚀 Performans Optimizasyonları

### 1. Asenkron İşlemler
HTTP istekleri asenkron yapılır (`asyncio`, `httpx`).

### 2. Rate Limiting
Polite mode ile sunucular korunur.

### 3. Maksimum İstek Sınırı
Kullanıcı tanımlı maksimum istek sayısı.

### 4. Timeout Koruması
Zaman aşımı ile sonsuz beklemeler önlenir.

## 📊 Veri Modelleri

Tüm veri modelleri `Pydantic` kullanılarak tanımlanmıştır:

- `Finding`: Bulunan güvenlik sorunu
- `CookieInfo`: Cookie bilgisi
- `HeaderAnalysis`: Header analizi sonucu
- `TLSInfo`: TLS bilgisi
- `DNSInfo`: DNS bilgisi
- `PageInfo`: Sayfa bilgisi
- `SecurityScore`: Güvenlik skoru
- `ScanResult`: Tam tarama sonucu

Bu modeller tip güvenliği sağlar ve otomatik validasyon yapar.

## 🔧 Genişletilebilirlik

### Yeni Analizci Ekleme

1. Yeni analizci sınıfı oluşturun (örn: `WAFAnalyzer`)
2. `WebSecurityScanner`'da analizciyi çağırın
3. Bulguları toplama listesine ekleyin
4. Test edin

### Yeni Rapor Formatı Ekleme

1. `SecurityReporter`'da yeni metod oluşturun (örn: `generate_pdf_report`)
2. Rapor formatını implement edin
3. CLI'da yeni seçenek ekleyin (örn: `--pdf`)
4. Test edin

### Yeni Skorlama Kuralı Ekleme

1. `SecurityScorer`'da yeni kural ekleyin
2. `scoring_model` dict'ini güncelleyin
3. `docs/scoring.md`'yi güncelleyin
4. Test edin

## 🧪 Test Stratejisi

### 1. Unit Tests
Her analizci bağımsız test edilir.

### 2. Integration Tests
Bileşenlerin birbirleriyle çalışması test edilir.

### 3. E2E Tests
Tam tarama süreci test edilir.

## 📝 Logging ve Debugging

- Tüm önemli işlemler loglanır
- Hata mesajları Türkçe ve anlaşılır
- Debug mode için detaylı logging

## 🎯 Gelecek İyileştirmeler

1. **PDF Rapor Export**: Raporları PDF formatında dışa aktarma
2. **Web UI**: Web tabanlı arayüz
3. **Trend Analizi**: Zaman içinde güvenlik trendleri
4. **Benchmarking**: Sektör ortalamaları ile karşılaştırma
5. **API**: RESTful API endpoint'leri
6. **Database**: Sonuçları saklama ve karşılaştırma

---

Bu mimari, TR-Pasif Web Güvenlik Skoru aracının ölçeklenebilir, bakımı kolay ve güvenli olmasını sağlar.