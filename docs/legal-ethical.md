# Yasal ve Etik Sınırlar

Bu doküman, TR-Pasif Web Güvenlik Skoru aracının yasal ve etik sınırlarını açıklar.

## ⚖️ Temel Prensipler

### 1. Sadece Pasif Tarama
Bu araç **sadece** pasif tarama yapar. Aktif saldırı veya istismar yoktur.

### 2. Yasal İzin Gerekli
Bu aracı **sadece** şu sistemlerde kullanabilirsiniz:
- ✅ Kendi sahibi olduğunuz sistemler
- ✅ Açıkça test izni aldığınız sistemler
- ✅ Public test ortamları
- ❌ Başkasına ait sistemler (izinsiz)
- ❌ Üretim sistemler (izinsiz)

### 3. Sorumluluk Sizin
Bu aracı kullanarak herhangi bir yasayı veya etik kuralı ihlal etmekten **tamamen siz sorumlusunuz**.

## ✅ Bu Tool Ne Yapar

### Pasif HTTP/HTTPS Analizi
- ✅ HTTP/HTTPS başlıklarını okur
- ✅ Cookie'leri toplar (maskelenmiş)
- ✅ Sayfa içeriğini indirir (GET isteği)
- ✅ Redirect zincirini izler

### DNS Güvenlik Kayıtları
- ✅ SPF kaydını sorgular
- ✅ DKIM kaydını sorgular
- ✅ DMARC kaydını sorgular
- ✅ CAA kaydını sorgular
- ✅ MX kaydını sorgular

### Sayfa Yapısı Analizi
- ✅ Form varlığını tespit eder
- ✅ Iframe varlığını tespit eder
- ✅ External script'leri listeler
- ✅ Mixed content kontrolü yapar

### Standart Path Kontrolleri
- ✅ `/robots.txt` var/yok kontrol
- ✅ `/sitemap.xml` var/yok kontrol
- ✅ `/.well-known/security.txt` var/yok kontrol
- ✅ `/login` var/yok kontrol
- ✅ `/admin` var/yok kontrol

## ❌ Bu Tool Ne YAPMAZ

### Aktif Saldırı
- ❌ Brute-force denemeleri
- ❌ Credential stuffing
- ❌ Login denemeleri
- ❌ Password guessing

### İstismar Denemeleri
- ❌ SQL Injection testleri
- ❌ XSS payload fırlatma
- ❌ CSRF token çalma
- ❌ SSRF exploit denemesi

### Agresif Tarama
- ❌ Rate limit zorlama
- ❌ DDoS benzeri yük
- ❌ Yoğun wordlist brute-force
- ❌ Gizli dizin keşfi (yoğun)

### Veri Çalma
- ❌ Database sızıntısı
- ❌敏感 bilgileri toplama
- ❌ User data çalma
- ❌ Password çalma

## ⚖️ Yasal Çerçeve

### Türkiye Cumhuriyeti Kanunları

#### TCK Madde 243 - Bilgisayar Sistemlerine Giriş
> Bilgisayar sistemlerine, veriye veya haberleşmeye hukuka aykırı olarak giren veya orada kalan kimseye, bir yıla kadar hapis veya adlî para cezası verilir.

**Bu araçla ihlal etmezsiniz çünkü:**
- Sadece public URL'lere GET isteği yapar
- Herhangi bir sisteme hukuka aykırı giriş yapmaz
- SQL injection, XSS gibi istismar denemez

#### TCK Madde 244 - Sistemi Engelleme, Bozma, Verileri Yok Etme
> Bir bilişim sisteminin çalışmasını engelleyen veya durduran, sistemdeki verileri bozan, yok eden, değiştiren, erişilmez kılan veya hukuka aykırı olarak veren kimseye, iki yıldan beş yıla kadar hapis cezası verilir.

**Bu araçla ihlal etmezsiniz çünkü:**
- Sistemin çalışmasını engellemez
- Verileri bozmaz, yok etmez, değiştirmez
- Sadece okuma (read-only) işlem yapar

#### TCK Madde 245 - Kredi Kartı veya Banka Kartının Kötüye Kullanımı
> Başkasına ait kredi kartı veya banka kartını kullanan kimseye, iki yıldan beş yıla kadar hapis ve on bin güne kadar adlî para cezası verilir.

**Bu araçla ihlal etmezsiniz çünkü:**
- Kredi kartı veya banka kartı bilgilerini toplamaz
- Payment işlemleri yapmaz
- Financial data çalmaz

#### 6698 Sayılı Kişisel Verilerin Korunması Kanunu
> Kişisel verilerin işlenmesinde, ilgili kişinin açık rızası gereklidir.

**Bu araçla ihlal etmezsiniz çünkü:**
- Kişisel verileri toplamaz
- Cookie'leri maskeler (değerleri gizler)
- Sadece teknik güvenlik bilgilerini toplar

### Uluslararası Kanunlar

#### CFAA (Computer Fraud and Abuse Act) - ABD
> Yetkisiz bilgisayar erişimi yasağı

**Bu araçla uyumludur çünkü:**
- Sadece public web sunucularına erişir
- Yetkisiz erişim (login bypass vb.) yapmaz
- Public URL'lere GET isteği yapar

#### GDPR (General Data Protection Regulation) - AB
> Kişisel verilerin korunması

**Bu araçla uyumludur çünkü:**
- Kişisel verileri toplamaz
- Cookie'leri maskele
- Sadece teknik analiz yapar

## 🎯 Etik Kullanım Kılavuzu

### Doğru Kullanım ✅

```
1. Kendi sitenizi test edin
   web-scan scan https://example.com
   
2. Müşterinizden izin alın
   "Sitenizi güvenlik açısından test edebilir miyim?"
   
3. Test ortamında deneyin
   web-scan scan https://test.example.com
   
4. Sorumluluk almayı unutmayın
   "Bu rapor sadece bilgilendirme amaçlıdır."
```

### Yanlış Kullanım ❌

```
1. Başkasının sitesini izinsiz test etmeyin
   ❌ web-scan scan https://rakip-sitesi.com
   
2. Müşteri izni olmadan test etmeyin
   ❌ "Zaten güvenlik firmasıyım, izne gerek yok"
   
3. Production'da agresif test yapmayın
   ❌ web-scan scan https://example.com --max-requests 1000
   
4. Bulgu abartmaktan kaçının
   ❌ "Siteniz hacklenecek, hemen düzeltin!"
```

## 📝 İzin Mektubu Şablonu

### Müşteri İzni

```
TARİH: DD/MM/YYYY
KİME: [Şirket Adı]
KONU: Web Sitesi Güvenlik Testi İzni

Sayın [Yetkili Kişi],

[Şirketiniz], [Müşteri Şirketi]'nin web sitesi [URL] için
pasif güvenlik testi yapma iznini talep etmektedir.

**Test Kapsamı:**
- Pasif HTTP/HTTPS analizi
- Header ve cookie kontrolü
- DNS güvenlik kayıtları
- Sayfa yapısı analizi
- Aktif saldırı YOKTUR

**Testin Yapılmayacağı Şeyler:**
- Brute-force denemeleri
- SQL Injection, XSS gibi istismarlar
- Veri çalma veya değiştirme
- Sistemi engelleme veya bozma

**Sonuçlar:**
- Test sonuçları sadece [Müşteri Şirketi] ile paylaşılacaktır
- Üçüncü şahıslarla paylaşılmayacaktır
- Test sonrasında rapor [Müşteri Şirketi]'ne sunulacaktır

İzniniz için teşekkür ederiz.

Saygılarımla,

[Adınız Soyadınız]
[Unvanınız]
[Şirketiniz]
```

## 🚨 Yasal Riskler

### İzinsiz Tarama Yaparsanız

1. **Cezai Sorumluluk**
   - TCK 243: 1 yıl hapis veya adli para cezası
   - TCK 244: 2-5 yıl hapis cezası
   - KVKK: 1.500.000 TL'ye kadar para cezası

2. **Sivil Sorumluluk**
   - Maddi tazminat davaları
   - Manevi tazminat davaları
   - İş kaybı talepleri

3. **Mesleki Sorumluluk**
   - Meslekten men cezası
   - Lisans iptali
   - İtibar kaybı

## 🛡️ Korunma Yöntemleri

### Tarama Yapmadan Önce

1. **İzin Alın**
   - Yazılı izin alın
   - Kapsamı netleştirin
   - Sorumlulukları belirleyin

2. **Sözleşme Yapın**
   - Gizlilik anlaşması imzalayın
   - Sorumluluk reddi belgesi alın
   - Sigorta yaptırın

3. **Test Ortamı Kullanın**
   - Production yerine test ortamında deneyin
   - Staging environment kullanın
   - Sandbox ortamda çalışın

### Tarama Sırasında

1. **Polite Mode Kullanın**
   ```bash
   web-scan scan https://example.com --polite
   ```

2. **Maksimum İstek Sınırlandırın**
   ```bash
   web-scan scan https://example.com --max-requests 15
   ```

3. **Zaman Aşımı Ayarlayın**
   ```bash
   web-scan scan https://example.com --timeout 10
   ```

### Tarama Sonrasında

1. **Raporu Gizli Tutun**
   - Sadece müşteriyle paylaşın
   - Public olarak yayınlamayın
   - Gereksiz yere dağıtmayın

2. **Sorumluluğu Reddedin**
   - Rapor disclaimer'i ekleyin
   - Profesyonel doğrulama önerin
   - Hukuki tavsiye verin

3. **Destek Sunun**
   - Bulguları açıklayın
   - Çözüm önerilerinde bulunun
   - Soruları yanıtlayın

## 📚 Referanslar

- [TCK 243-245 - Bilişim Suçları](https://www.mevzuat.gov.tr)
- [6698 Sayılı KVKK](https://www.kvkk.gov.tr)
- [CFAA - Computer Fraud and Abuse Act](https://www.law.cornell.edu/uscode/text/18/1030)
- [GDPR - General Data Protection Regulation](https://gdpr.eu/)
- [OWASP Legal Project](https://owasp.org/www-project-legal/)
- [ISTE - Ethical Hacking Guidelines](https://www.iste.org/)

## ✅ Kullanıcı Onayı

Bu aracı kullanarak aşağıdakileri kabul etmiş sayılırsınız:

1. Bu aracı sadece kendi sahip olduğum veya açıkça izin aldığım sistemlerde kullanacağım.
2. İzinsiz tarama yapmaktan doğacak tüm yasal sorumluluğu kabul ediyorum.
3. Bu araç tarafından üretilen raporların sadece bilgilendirme amaçlı olduğunu anlıyorum.
4. Raporlardaki bulguların profesyonel güvenlik uzmanları tarafından doğrulanması gerektiğini kabul ediyorum.
5. Bu aracı kullanarak herhangi bir yasayı veya etik kuralı ihlal etmekten tamamen sorumluyum.

---

⚠️ **Uyarı**: Bu doküman hukuki tavsiye değildir. Hukuki konularda bir avukata danışmanızı öneririz.