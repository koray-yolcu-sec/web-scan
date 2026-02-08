# Skorlama Modeli

Web-Scan, 0-100 arası bir puanlama sistemidir. Bu doküman, skorlama modelini detaylı olarak açıklar.

## 🎯 Temel Prensipler

### Başlangıç Puanı
- **Başlangıç puanı: 100**
- Her güvenlik eksikliği puanı düşürür
- Minimum puan: 0
- Maksimum puan: 100

### Puan Düşme Mekanizması
- Her bulgu `score_impact` değeri taşır (negatif)
- Tüm negatif etkiler toplanır
- Toplam puan = 100 + toplam_etki
- 0-100 aralığına clamp edilir

### Shark Mode 🦈
Shark mode aktifse, tüm negatif etkiler **%30 daha fazla** kırılır.
Bu mod daha katı standartlar uygular ve production için önerilir.

Örnek:
- Normal mode: -10 puan düşme
- Shark mode: -13 puan düşma (10 × 1.3)

## 📊 Kategorilere Göre Skor Düşmeleri

### 🔴 Kritik Eksikler

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| HTTPS yoksa | -35 | TLS | Şifreleme yok, kritik güvenlik açığı |
| CORS wildcard + credentials | -15 | Header | Tehlikeli CORS konfigürasyonu |
| HSTS yoksa | -10 | Header | MITM ve SSL stripping riski |
| CSP yoksa veya zayıfsa | -10 | Header | XSS savunması yok veya zayıf |
| X-Frame-Options yoksa | -8 | Header | Clickjacking koruması yok |

### 🍪 Cookie Güvenliği

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| Session cookie Secure eksik | -5 | Cookie | HTTP üzerinden çalınabilir |
| Session cookie HttpOnly eksik | -4 | Cookie | XSS ile çalınabilir |
| Session cookie SameSite eksik | -3 | Cookie | CSRF riski |

### 📋 Diğer Header'lar

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| X-Content-Type-Options yoksa | -5 | Header | MIME type sniffing riski |
| Referrer-Policy yoksa | -4 | Header | Referrer bilgisi sızması |
| Permissions-Policy yoksa | -3 | Header | API izin kontrolü yok |
| Permissions-Policy: camera açık | -1 | Header | Kamera API riski |
| Permissions-Policy: microphone açık | -1 | Header | Mikrofon API riski |
| Permissions-Policy: geolocation açık | -1 | Header | Konum API riski |

### 🔍 Bilgi Sızdırma

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| Server header versiyon bilgisi | -3 | Header | Server versiyonu açık |
| X-Powered-By disclosure | -1 | Header | Framework bilgisi sızıyor |
| Meta generator versiyon | -1 | Page | CMS/Framework versiyonu açık |

### 🌐 DNS Güvenliği

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| SPF eksik | -3 | DNS | Email spoofing riski |
| DMARC eksik | -5 | DNS | Email spoofing savunması yok |
| DMARC policy none | -2 | DNS | Sadece izleme modu |
| DKIM eksik | -2 | DNS | Email kimlik doğrulama yok |
| CAA eksik | -1 | DNS | Sertifika otoritesi kontrolü yok |

### 📄 Sayfa Yapısı

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| Mixed content | -8 | Page | HTTPS sayfada HTTP kaynak |
| Form GET methodu | -2 | Page | Hassas veriler için riskli |

### 🔒 TLS/Sertifika

| Bulgu | Puan Düşme | Kategori | Açıklama |
|-------|-----------|----------|----------|
| HTTP açık (HTTPS var) | -5 | TLS | Redirect yok |
| Sertifika dolmuş | -20 | TLS | Sertifika geçersiz |
| Sertifika yakında dolacak | -5 | TLS | 30 günden az süre |

## 🎨 Renk Eşikleri

### 🔴 Kırmızı: Düşük Güvenlik (0-49)
- Kritik güvenlik eksiklikleri var
- Acil düzeltme gerekli
- Production için uygun değil

### 🟡 Sarı: Orta Güvenlik (50-79)
- Temel güvenlik önlemleri var
- Önemli iyileştirmeler gerekli
- Production için iyileştirme gerekli

### 🟢 Yeşil: İyi Güvenlik (80-100)
- Genel olarak güvenli
- Küçük iyileştirmeler yapılabilir
- Production için uygun

## 📈 Skor Hesaplama Örnekleri

### Örnek 1: Kritik Açıklar
```
Başlangıç: 100
HTTPS yok: -35
HSTS yok: -10
CSP yok: -10
----------
Toplam: 45 (Kırmızı)
```

### Örnek 2: Orta Güvenlik
```
Başlangıç: 100
X-Frame-Options yok: -8
Referrer-Policy yok: -4
SameSite eksik: -3
----------
Toplam: 85 (Yeşil)
```

### Örnek 3: Shark Mode
```
Başlangıç: 100
HSTS yok: -10 × 1.3 = -13
CSP yok: -10 × 1.3 = -13
----------
Toplam: 74 (Sarı)
```

## 🎯 Önceliklendirme Sistemi

### Top Priorities (Öncelik Listesi)
- Kırmızı (Kritik) bulgular
- -5'ten daha büyük etkiye sahip bulgular
- Etkiye göre sıralı (en büyük etki önce)

### Quick Wins (Hızlı Kazanımlar)
- Header ve cookie kategorisi
- Eksiklik/missing bulgular
- Kolay düzeltilebilir bulgular
- İlk 5 bulgu

### Kategori Özeti
- **Kritik**: Etki ≥ 20 ve Kırmızı
- **Yüksek**: Etki < 20 ve Kırmızı
- **Orta**: Sarı
- **Düşük**: Yeşil

## 🔧 Skor Modelini Özelleştirme

### Yeni Kural Ekleme
```python
# scorer/security_scorer.py
self.scoring_model = {
    # ... mevcut kurallar ...
    'yeni_bulgu': -5,  # Yeni kural
}
```

### Puanı Değiştirme
```python
# Mevcut kuralı güncelle
self.scoring_model['https_missing'] = -40  # -35 yerine -40
```

### Shark Mode Çarpanını Değiştirme
```python
# Varsayılan: 1.3 (%30 daha fazla kırma)
self.shark_mode_multiplier = 1.5  # %50 daha fazla kırma
```

## 📊 Skor Dağılımı Analizi

### İdeal Güvenli Site (85-100)
- HTTPS + HSTS + CSP
- Tüm cookie'lerde Secure/HttpOnly/SameSite
- Tüm header'lar mevcut
- Bilgi sızdırma yok
- DNS kayıtları tam

### Orta Güvenlikli Site (50-79)
- HTTPS var ama HSTS eksik
- Bazı header'lar eksik
- Cookie'lerde flag eksiklikleri
- Bazı DNS kayıtları eksik

### Düşük Güvenlikli Site (0-49)
- HTTPS yok
- Kritik header'lar eksik
- Cookie güvenliği yok
- Mixed content
- DNS kayıtları yok

## 🎓 Skor İyileştirme Stratejileri

### Hızlı İyileştirmeler (Top 5)
1. **HTTPS Ekle**: +35 puan
2. **HSTS Ekle**: +10 puan
3. **CSP Ekle**: +10 puan
4. **X-Frame-Options Ekle**: +8 puan
5. **X-Content-Type-Options Ekle**: +5 puan
**Potansiyel Kazanç: +68 puan**

### Orta Vadeli İyileştirmeler
1. **Cookie Güvenliği**: +12 puan
2. **Referrer-Policy Ekle**: +4 puan
3. **Permissions-Policy Ekle**: +3 puan
4. **DNS Kayıtları**: +11 puan
5. **Mixed Content Düzelt**: +8 puan
**Potansiyel Kazanç: +38 puan**

### Uzun Vadeli İyileştirmeler
1. **Sertifika Yönetimi**: +25 puan
2. **Bilgi Sızdırma Düzelt**: +5 puan
3. **Form Güvenliği**: +2 puan
**Potansiyel Kazanç: +32 puan**

## 🚨 Edge Case'ler

### Minimum Puan
- Puan 0'ın altına düşerse, 0'a clamp edilir
- Örnek: -150 etki → 0 puan

### Maksimum Puan
- Puan 100'ün üzerine çıkarsa, 100'e clamp edilir
- Örnek: +20 etki → 100 puan

### Sıfır Etki
- Bazı bulgular sıfır etkiye sahip olabilir (bilgilendirme amaçlı)
- Bu bulgular skoru etkilemez

## 🔄 Skor Güncellemeleri

Skorlama modeli zaman içinde güncellenebilir:

1. **Yeni tehditler**: Yeni güvenlik tehditleri için yeni kurallar
2. **Standart değişiklikleri**: OWASP, W3C standartlarına göre güncellemeler
3. **Kullanıcı geri bildirimi**: Topluluk geri bildirimlerine göre ayarlamalar
4. **Benchmark verileri**: Sektör ortalamalarına göre hizalama

## 📚 Referanslar

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Security Headers](https://securityheaders.com/)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [SSL Labs](https://www.ssllabs.com/ssltest/)

---

Bu skorlama modeli, TR-Pasif Web Güvenlik Skoru aracının güvenlik değerlendirmesinde standart ve şeffaf bir yaklaşım sağlar.