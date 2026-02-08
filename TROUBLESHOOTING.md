# Sorun Giderme Rehberi (Troubleshooting)

Bu doküman, **web-scan** kurulumu ve çalıştırılması sırasında
karşılaşılabilecek yaygın sorunları ve pratik çözüm yollarını içerir.

---

## ❗ `zsh: command not found: web-scan`

### Sebep
`web-scan` bir Python CLI aracıdır. Komut olarak çalışabilmesi için
paketin doğru şekilde kurulmuş olması gerekir.

### Çözüm
Proje dizininde (`pyproject.toml` dosyasının bulunduğu klasör) aşağıdaki komutu çalıştırın:

```bash
pip install -e .
```
Kurulumdan sonra kontrol edin:
```bash
which web-scan
```

## Alternatif (doğrudan çalıştırma)
CLI komutu tanımlı değilse aşağıdaki şekilde de çalıştırabilirsiniz:
```bash
python -m web_scan.cli
```
## ❗ ERROR: Package 'web-scan' requires a different Python version

### Örnek hata:

' ERROR: Package 'web-scan' requires a different Python: 3.9.x not in '>=3.11' '

### Sebep:

web-scan, modern Python özelliklerini kullandığı için
Python 3.11 ve üzeri gerektirir.

### Çözüm (önerilen yöntem)

Python 3.11 kurup sanal ortamı yeniden oluşturun:
```bash
brew install python@3.11
python3.11 -m venv venv
source venv/bin/activate
pip install -e .
```

Kurulumdan sonra sürümü kontrol edin:
```bash
python --version
```

### ❗ Sanal ortam (venv) yanlış Python sürümüyle oluşturulmuş

### Sebep :

venv, eski bir Python sürümü ile oluşturulmuş olabilir.

### Çözüm :

Mevcut sanal ortamı silip Python 3.11 ile yeniden oluşturun:
```bash
deactivate
rm -rf venv
python3.11 -m venv venv
source venv/bin/activate
pip install -e .
```

## ❗ pip veya python komutu bulunamıyor

### Sebep :

Python veya pip sistem PATH’ine ekli olmayabilir.

### Kontrol :
```bash
python3 --version
pip3 --version
```
### Çözüm :
```bash
python3 -m pip install --upgrade pip
```

## ❗ web-scan çalışıyor ama çıktı üretmiyor

### Sebep :
Hedef URL erişilebilir olmayabilir
Zaman aşımı veya istek limitleri çok düşük ayarlanmış olabilir

### Çözüm :

Detaylı çıktı ile tekrar deneyin:
```bash
web-scan scan https://example.com --verbose
```
## ❗ Ağ veya izin (permission) hataları

### Sebep :

- VPN, kurumsal ağlar veya güvenlik duvarları dış istekleri engelliyor olabilir.

### Çözüm :
- VPN’i geçici olarak kapatın
- Farklı bir ağdan deneyin
- DNS çözümlemesini kontrol edin:
- ping example.com

## 📌 En İyi Uygulamalar

- Her zaman sanal ortam (venv) kullanın
- Python sürümünüzün >= 3.11 olduğundan emin olun
- Geliştirme sırasında şu komutu tercih edin:
```bash
pip install -e .
```

---

## Yardım Almak

Sorun devam ediyorsa GitHub üzerinde bir Issue açarken şu bilgileri ekleyin:

- İşletim sistemi
- Python sürümü (python --version)
- Aldığınız hata çıktısının tamamı
- Detaylı log için:
```bash
web-scan scan https://example.com --verbose
```
