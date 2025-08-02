# 🔒 Zafiyet Bulucu Pro

Modern ve kullanıcı dostu bir güvenlik analizi aracı. Shodan, MITRE CVE ve LLM entegrasyonu ile kapsamlı zafiyet analizi yapabilirsiniz.

## 🚀 Özellikler

- **🔍 IP Zafiyet Analizi**: Port tarama, servis tespiti, CVE analizi ve LLM çözüm önerileri
- **📊 Açık Port Taraması**: Hedef IP'deki açık portları listeleme
- **🌐 Shodan Arama**: Genel arama ile ülke, şehir, ürün ve port bilgileri
- **🤖 LLM Entegrasyonu**: CVE'ler için yapay zeka destekli çözüm önerileri
- **💾 Rapor Kaydetme**: Analiz sonuçlarını dosyaya kaydetme
- **🎨 Modern UI**: Koyu tema ile modern kullanıcı arayüzü

## 📋 Gereksinimler

```bash
pip install -r requirements.txt
```

## ⚙️ Kurulum

### 1. API Anahtarlarını Ayarlayın

Proje dizininde `.env` dosyası oluşturun:

```env
# Shodan API Anahtarı
SHODAN_API_KEY=your_shodan_api_key_here

# Groq API Anahtarı (LLM için)
GROQ_API_KEY=your_groq_api_key_here
```

### 2. API Anahtarlarını Alın

#### Shodan API Anahtarı:
1. https://account.shodan.io/register adresine gidin
2. Ücretsiz hesap oluşturun
3. API anahtarınızı kopyalayın
4. `.env` dosyasında `SHODAN_API_KEY` değerini güncelleyin

#### Groq API Anahtarı (LLM için):
1. https://console.groq.com/ adresine gidin
2. Ücretsiz hesap oluşturun
3. API anahtarınızı kopyalayın
4. `.env` dosyasında `GROQ_API_KEY` değerini güncelleyin

### 3. Nmap Kurulumu

Windows için:
```bash
# Nmap'i indirin ve PATH'e ekleyin
# https://nmap.org/download.html
```

Linux/Mac için:
```bash
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # Mac
```

## 🎯 Kullanım

### Uygulamayı Başlatın:
```bash
python tinder_ui.py
```

### Ana Menü Seçenekleri:

1. **🔍 IP Zafiyet Analizi**
   - IP adresi girin
   - Port taraması yapın
   - Servisleri bulun
   - CVE analizi yapın
   - LLM çözüm önerileri alın

2. **📊 Açık Port Taraması**
   - Hedef IP'deki açık portları listele

3. **🌐 Shodan Arama**
   - Genel arama terimleri ile Shodan'da arama yapın
   - Ülke, şehir, ürün ve port bilgilerini görün

## 🔧 Sorun Giderme

### Shodan Arama Sorunları:
- ✅ API anahtarınızın doğru olduğundan emin olun
- ✅ İnternet bağlantınızı kontrol edin
- ✅ `.env` dosyasının proje dizininde olduğunu kontrol edin

### LLM Analizi Sorunları:
- ✅ Groq API anahtarınızın doğru olduğundan emin olun
- ✅ API limitlerini kontrol edin

### Nmap Sorunları:
- ✅ Nmap'in sistem PATH'inde olduğundan emin olun
- ✅ Windows'ta Nmap'i yönetici olarak çalıştırın

## 📁 Dosya Yapısı

```
ZafiyetBulucu/
├── tinder_ui.py          # Ana uygulama
├── Api_Shodan.py         # Shodan API fonksiyonları
├── Main.py               # MITRE CVE ve LLM fonksiyonları
├── output_capture.py     # Çıktı yakalama sistemi
├── requirements.txt      # Python bağımlılıkları
├── .env                  # API anahtarları (siz oluşturun)
└── README.md            # Bu dosya
```

## 🛡️ Güvenlik Notları

- API anahtarlarınızı güvenli tutun
- Sadece kendi sistemlerinizde test yapın
- Yasal sınırlar içinde kalın
- Etik hacking prensiplerini takip edin

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## ⚠️ Sorumluluk Reddi

Bu araç sadece eğitim ve güvenlik testleri için tasarlanmıştır. Kullanıcılar kendi sorumluluklarında kullanırlar. Geliştirici herhangi bir zarardan sorumlu değildir. 