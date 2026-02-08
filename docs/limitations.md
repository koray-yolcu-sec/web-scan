# Sınırlamalar ve Bilinen Sorunlar

Bu doküman, TR-Pasif Web Güvenlik Skoru aracının sınırlamalarını açıklar.

## 🔍 Genel Sınırlamalar

### 1. Pasif Tarama Kısıtlamaları

#### Sadece Görüneni Test Eder
- ✅ HTTP header'larını okur
- ✅ Cookie'leri toplar
- ✅ DNS kayıtlarını sorgular
- ❌ Backend kodunu analiz etmez
- ❌ Database yapısını görmüyor
- ❌ Server konfigürasyonunu doğrudan kontrol etmez

#### Aktif Test Yapmaz
- ❌ SQL injection testleri yok
- ❌ XSS payload fırlatma yok
- ❌ Brute-force denemeleri yok
- ❌ Login bypass denemeleri yok
- ❌ CSRF token theft yok

**Sonuç**: Arka planda çalışan güvenlik açıklarını tespit edemez.

### 2. Teknik Kısıtlamalar

#### HTTP/HTTPS Sınırlamaları
- Sadece GET isteği yapar
- POST/PUT/DELETE request'leri test etmez
- WebSocket bağlantılarını analiz etmez
- HTTP/2 ve HTTP/3 detaylı analiz sınırlı

#### DNS Sınırlamaları
- Sadece public DNS kayıtlarını sorgular
- Internal DNS sorgulamaları yapmaz
- DNS cache poisoning testi yapmaz
- DNSSEC doğrulaması yapmaz

#### TLS/Sertifika Sınırlamaları
- Sertifika zinciri detaylı analiz yapmaz
- TLS version downgrade testi yapmaz
- Cipher suite detaylı kontrol yapmaz
- OCSP ve CRL doğrulama yapmaz

### 3. Kapsam Sınırlamaları

#### Test Edilen Path'ler
Varsayılan olarak sadece şu path'ler kontrol edilir:
- `/` (ana sayfa)
- `/robots.txt`
- `/sitemap.xml`
- `/.well-known/security.txt`
- `/login`
- `/admin`

**Sınırlama**: Bu path'ler dışındaki endpoint'ler test edilmez.

#### Test Edilen Kategoriler
- ✅ Header güvenliği
- ✅ Cookie güvenliği
- ✅ TLS/HTTPS
- ✅ DNS güvenliği
- ✅ Sayfa yapısı
- ❌ Backend güvenliği
- ❌ Database güvenliği
- ❌ API güvenliği (detaylı)
- ❌ Mobile app güvenliği

## 🚫 Tespit Edemeyeceği Güvenlik Açıkları

### Web Uygulaması Açıkları

#### 1. SQL Injection
**Neden tespit edilemez?**
- Aktif payload fırlatma gerekir
- Database yanıtını analiz etmek gerekir
- Error-based SQLi testi gerekir

**Örnek**:
```sql
-- Bu test edilmez
SELECT * FROM users WHERE id = 1' OR '1'='1
```

#### 2. Cross-Site Scripting (XSS)
**Neden tespit edilemez?**
- Aktif payload fırlatma gerekir
- Script'in çalışıp çalışmadığını test etmek gerekir
- XSS payload çeşitleri çok fazla

**Örnek**:
```html
<!-- Bu test edilmez -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

#### 3. Cross-Site Request Forgery (CSRF)
**Neden tespit edilemez?**
- Token doğrulama testi gerekir
- Aktif request göndermek gerekir
- Referer header manipülasyonu gerekir

**Örnek**:
```html
<!-- Bu test edilmez -->
<form action="https://example.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="hacker">
</form>
```

#### 4. Authentication/Authorization Açıkları
**Neden tespit edilemez?**
- Login denemesi gerekir
- Session hijacking testi gerekir
- Privilege escalation testi gerekir

**Örnek**:
```http
# Bu test edilmez
POST /admin/delete HTTP/1.1
Cookie: session=attacker_session
```

### Backend Açıkları

#### 1. Business Logic Açıkları
**Neden tespit edilemez?**
- Backend mantığını görmek gerekir
- Transaction flow analiz etmek gerekir
- Race condition testi gerekir

**Örnek**:
```python
# Bu test edilmez
def transfer_money(from_user, to_user, amount):
    # Race condition test edilmez
    balance[from_user] -= amount
    balance[to_user] += amount
```

#### 2. Authorization Açıkları
**Neden tespit edilemez?**
- Role-based access control testi gerekir
- Horizontal/vertical privilege escalation testi gerekir
- API endpoint authorization testi gerekir

**Örnek**:
```http
# Bu test edilmez
GET /api/user/1234 HTTP/1.1
Cookie: session=user_5678_session
```

#### 3. File Upload Açıkları
**Neden tespit edilemez?**
- Dosya upload denemesi gerekir
- File type validation testi gerekir
- RCE testi gerekir

**Örnek**:
```php
<!-- Bu test edilmez -->
<form action="upload.php" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
</form>
```

### Infrastructure Açıkları

#### 1. Server Misconfiguration
**Neden tespit edilemez?**
- Server konfigürasyonunu doğrudan görmek gerekir
- Nginx/Apache config dosyalarına erişim gerekir
- Server side error'ları analiz etmek gerekir

**Örnek**:
```nginx
# Bu test edilmez
server {
    server_name example.com;
    # Nginx config doğrudan erişilemez
}
```

#### 2. Network Security Açıkları
**Neden tespit edilemez?**
- Port scanning gerekir
- Network topolojisi analiz etmek gerekir
- Firewall bypass testi gerekir

**Örnek**:
```bash
# Bu test edilmez
nmap -p- example.com
```

#### 3. Container/Orchestration Açıkları
**Neden tespit edilemez?**
- Container güvenliği testi gerekir
- Kubernetes config analiz etmek gerekir
- Docker security audit gerekir

**Örnek**:
```yaml
# Bu test edilmez
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
  - name: vulnerable
    image: vulnerable:latest
```

## ⚠️ Yanlış Pozitif/Negatifler

### Yanlış Pozitifler (False Positives)

#### 1. CSP "Zayıf" Algılanabilir
**Senaryo**: CSP var ama inline script'e izin veriyor.
**Gerçek**: Bu purposefully yapılmış olabilir.
**Neden**: Bazı siteler inline script kullanmak zorunda kalabilir.

#### 2. Cookie "Güvensiz" Algılanabilir
**Senaryo**: Session cookie'de SameSite yok.
**Gerçek**: Site subdomain'ler arasında paylaşım yapıyor olabilir.
**Neden**: Cross-subdomain gereksinimi olabilir.

#### 3. Mixed Content "Riskli" Algılanabilir
**Senaryo**: HTTPS sayfada HTTP img var.
**Gerçek**: Img'ler hassas değil, sadece dekoratif.
**Neden**: Performance için HTTP img kullanılabilir.

### Yanlış Negatifler (False Negatives)

#### 1. CORS Açığı Kaçırabilir
**Senaryo**: Dynamic origin kontrolü.
**Gerçek**: Origin spesifik domain'e izin veriyor ama logic hatalı.
**Neden**: Sadece header'ı okuyor, logic'i test etmiyor.

#### 2. JWT Açığı Kaçırabilir
**Senaryo**: JWT token weak secret key.
**Gerçek**: Token imzalanmış ama secret zayıf.
**Neden**: Token cryptografik analiz yapmıyor.

#### 3. SSRF Açığı Kaçırabilir
**Senaryo**: URL parametresi ile internal request.
**Gerçek**: `?url=http://localhost:8080` internal erişim sağlıyor.
**Neden**: Aktif request göndermiyor.

## 🔬 Teknik Limitasyonlar

### HTTP Kütüphanesi Sınırlamaları
- `httpx` kütüphanesi kullanılıyor
- JavaScript-rendered content analiz etmiyor
- Dynamic content (AJAX, Fetch) görmüyor
- WebSocket bağlantılarını analiz etmiyor

### BeautifulSoup Sınırlamaları
- Sadece static HTML'i parse ediyor
- JavaScript-oluşturulan content'i görmüyor
- Shadow DOM'u analiz etmiyor
- Server-side rendering (SSR) gerekiyor

### DNS Kütüphanesi Sınırlamaları
- `dnspython` kütüphanesi kullanılıyor
- Sadece standard DNS sorguları yapıyor
- DNS over HTTPS (DoH) yapmıyor
- DNS over TLS (DoT) yapmıyor

### TLS Kütüphanesi Sınırlamaları
- `httpx` TLS client'ı kullanılıyor
- Sertifika detaylı analiz sınırlı
- Cipher suite seçimi kontrol edemiyor
- TLS protocol downgrade testi yapamıyor

## 📊 Skorlama Sınırlamaları

### Skor Modeli Kısıtlamaları
- Skor modeli subjektif olabilir
- Sektöre göre farklı skor gerekebilir
- Site tipine göre (e-commerce, blog vb.) değişebilir
- Risk toleransı değişebilir

### Skor Yorumlama Kısıtlamaları
- Düşük skor mutlaka hacklenebilir demek değil
- Yüksek skor mutlaka güvenli demek değil
- Skor sadece tavsiye niteliğinde
- Profesyonel audit gerekli

## 🌐 Çevre Sınırlamaları

### Network Sınırlamaları
- Internet erişimi gerekli
- DNS resolution gerekli
- Firewall/Proxy engelleyebilir
- Rate limiting engelleyebilir

### Target Site Sınırlamaları
- Site çok yavaşsa timeout olabilir
- Site çok büyüksa tarama uzayabilir
- Site çok agresifse engelleyebilir
- Site down ise tarama başarısız

### Resource Sınırlamaları
- CPU kullanımı
- Memory kullanımı
- Disk alanı (log'lar)
- Network bandwidth

## 🔮 Gelecek Geliştirmeler

### Planlanan Özellikler
1. **API Security Testing**
   - REST API endpoint analiz
   - GraphQL query analiz
   - API rate limiting test

2. **Mobile App Security**
   - APK/IPA analiz
   - Mobile API test
   - Certificate pinning kontrol

3. **Infrastructure Security**
   - Cloud config analiz (AWS, GCP, Azure)
   - Container security scan
   - Kubernetes security audit

4. **Advanced Attacks**
   - (İzinsiz YOK, sadece izinli test ortamında)
   - SQL injection test
   - XSS payload test
   - CSRF token test

### Araştırılan Özellikler
1. **AI/ML Security**
   - Anomaly detection
   - Pattern recognition
   - Threat intelligence

2. **Continuous Monitoring**
   - Periodic scanning
   - Alert system
   - Trend analysis

3. **Integration**
   - CI/CD pipeline
   - DevSecOps tools
   - Bug bounty platforms

## ✅ Best Practices

### Tool'ı Doğru Kullanma

1. **Complementary Tool Olarak Kullanın**
   - Bu tool yalnız başına yeterli değil
   - Aktif test araçlarıyla kombinasyon yapın
   - Profesyonel audit gerekli

2. **Sonuçları Doğru Yorumlayın**
   - Düşük skor = acil düzeltme
   - Yüksek skor = hala incele
   - Skor = tavsiye, garanti değil

3. **Düzenli Tarama Yapın**
   - Aylık tarama
   - Değişiklik sonrası tarama
   - Yeni özellik sonrası tarama

### Sonuçların Doğrulanması

1. **Manual Doğrulama**
   - Bulguları manuel kontrol edin
   - False positive'ları filtreleyin
   - Gerçek riski değerlendirin

2. **Professional Audit**
   - Güvenlik firmasıyla çalışın
   - Penetration testing yaptırın
   - Third-party assessment alın

3. **Continuous Improvement**
   - Bulguları düzeltin
   - Yeni tarama yapın
   - İyileştirmeyi takip edin

## 📚 Referanslar

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)

---

**Önemli**: Bu tool, profesyonel güvenlik testlerinin yerini almaz. Her zaman profesyonel güvenlik uzmanlarıyla çalışın.