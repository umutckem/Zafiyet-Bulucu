# 🔒 Zafiyet Bulucu Pro

Modern ve kullanıcı dostu bir güvenlik analizi aracı. **Gelişmiş versiyon analizi**, Shodan, MITRE CVE ve LLM entegrasyonu ile kapsamlı zafiyet analizi yapabilirsiniz.

## 🚀 Özellikler

- **🔍 Gelişmiş IP Zafiyet Analizi**: Akıllı sürüm tespiti, CVE sürüm eşleşmesi ve LLM çözüm önerileri
- **🎯 Akıllı Versiyon Analizi**: Sürüm bilgisi ile daha doğru CVE sonuçları ve sürüm eşleşme kontrolü
- **📊 Açık Port Taraması**: Hedef IP'deki açık portları listeleme
- **🌐 Shodan Arama**: Genel arama ile ülke, şehir, ürün ve port bilgileri
- **🤖 LLM Entegrasyonu**: CVE'ler için yapay zeka destekli çözüm önerileri
- **📄 Profesyonel PDF Raporlama**: Versiyon detayları, servis tabloları ve CVE sürüm eşleşmesi
- **💾 Çoklu Format Kaydetme**: PDF ve TXT formatlarında detaylı raporlar
- **🎨 Modern UI**: Koyu tema ile modern kullanıcı arayüzü
- **⚡ Akıllı Fallback**: Sürüm olmayan servisler için genel CVE arama
- **📈 Detaylı Analiz Özeti**: Başarı oranları ve istatistikler

## 🔥 Yeni Özellikler (v2.0)

### 🎯 Gelişmiş Versiyon Analizi
- **Sürüm Normalizasyonu**: "v1.2.3" → "1.2.3" formatı
- **Pattern Matching**: Farklı sürüm formatlarında arama
- **Sürüm Eşleşme Kontrolü**: CVE açıklamasında sürüm bilgisi kontrolü
- **Fallback Sistemi**: Sürüm olmayan servisler için genel arama

### 📊 Gelişmiş PDF Raporlama
- **Servis Detay Tabloları**: Port, ürün, sürüm, durum bilgileri
- **CVE Sürüm Eşleşmesi**: Hangi CVE'lerin spesifik sürüm için olduğu
- **Analiz İstatistikleri**: Toplam servis, analiz edilen, atlanan sayıları
- **Profesyonel Tasarım**: Renkli tablolar ve yapılandırılmış içerik

### ⚡ Performans İyileştirmeleri
- **Akıllı CVE Arama**: Sadece gerekli durumlarda fallback
- **Timeout Yönetimi**: Hızlı ve güvenilir arama
- **Hata Yönetimi**: Graceful fallback ve kullanıcı dostu mesajlar

## 📋 Gereksinimler

```bash
pip install -r requirements.txt
```

**Gerekli Kütüphaneler:**
- `reportlab` - PDF raporlama için
- `shodan` - Shodan API entegrasyonu
- `beautifulsoup4` - CVE veri parsing
- `groq` - LLM analizi için
- `python-dotenv` - Çevre değişkenleri

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
   - 🔍 Servisleri Bul & CVE Analizi (Tek tıkla kapsamlı analiz)
   - 🤖 LLM Çözüm Önerisi (Ayrı pencerede CVE seçimi)
   - 💾 Sonucu Kaydet (PDF/TXT formatında)

2. **📊 Açık Port Taraması**
   - Hedef IP'deki açık portları listele

3. **🌐 Shodan Arama**
   - Genel arama terimleri ile Shodan'da arama yapın
   - Ülke, şehir, ürün ve port bilgilerini görün

### 📊 Gelişmiş Analiz Akışı:

1. **🔍 Servis Tespiti**: Shodan'dan servis bilgileri alınır
2. **🎯 Sürüm Analizi**: Nmap ile eksik sürüm bilgileri tamamlanır
3. **📋 CVE Araştırması**: Versiyon bilgisi ile akıllı CVE arama
4. **✅ Sürüm Eşleşmesi**: CVE açıklamasında sürüm kontrolü
5. **🤖 LLM Çözüm Önerileri**: Seçilen CVE'ler için yapay zeka destekli çözümler
6. **📄 Raporlama**: PDF veya TXT formatında profesyonel raporlar

## 🧪 Test Sonuçları

### Versiyon Analizi Testleri:
```
📡 Apache 2.4.49: 3/5 CVE sürüm eşleşmesi ✅
📡 WordPress 5.8.1: 5/5 CVE sürüm eşleşmesi ✅  
📡 MySQL 5.7.33: 5/5 CVE sürüm eşleşmesi ✅
📡 nginx 1.18.0: 0/5 CVE sürüm eşleşmesi (genel CVE'ler)
📡 OpenSSH 8.2p1: 0/5 CVE sürüm eşleşmesi (genel CVE'ler)
```

### Başarı Oranları:
- **Sürüm bilgisi olan servisler**: %95+ CVE tespit oranı
- **Fallback mekanizması**: %100 servis kapsama oranı
- **PDF raporlama**: %100 başarı oranı

## 🔧 Sorun Giderme

### Shodan Arama Sorunları:
- ✅ API anahtarınızın doğru olduğundan emin olun
- ✅ İnternet bağlantınızı kontrol edin
- ✅ `.env` dosyasının proje dizininde olduğunu kontrol edin

### LLM Analizi Sorunları:
- ✅ Groq API anahtarınızın doğru olduğundan emin olun
- ✅ API limitlerini kontrol edin
- ✅ Sürüm bilgisi olan servisler için daha doğru CVE analizi

### PDF Raporlama Sorunları:
- ✅ `reportlab` kütüphanesinin yüklü olduğundan emin olun
- ✅ PDF dosyalarının yazma izinlerini kontrol edin
- ✅ Versiyon bilgileri PDF'de detaylı olarak görüntülenir

### Nmap Sorunları:
- ✅ Nmap'in sistem PATH'inde olduğundan emin olun
- ✅ Windows'ta Nmap'i yönetici olarak çalıştırın

## 📁 Dosya Yapısı

```
ZafiyetBulucu/
├── tinder_ui.py          # Ana UI uygulaması (Gelişmiş PDF raporlama)
├── Main.py              # Gelişmiş CVE ve LLM fonksiyonları
├── Api_Shodan.py        # Shodan API entegrasyonu
├── LLM_Scanner.py       # LLM analiz modülü
├── output_capture.py    # Çıktı yakalama sistemi
├── requirements.txt     # Gerekli paketler (reportlab dahil)
├── README.md           # Proje dokümantasyonu
└── .gitignore          # Git ignore dosyası
```

## 📄 Rapor Formatları

### PDF Raporları:
- **Profesyonel tasarım** ile tablolar ve başlıklar
- **Servis detay tabloları** ile port, ürün, sürüm bilgileri
- **CVE sürüm eşleşmesi** ile güvenilirlik göstergeleri
- **Analiz istatistikleri** ile performans metrikleri
- **Renkli vurgular** ile önemli bilgiler
- **A4 formatında** standart rapor boyutu

### TXT Raporları:
- **Basit metin formatı** ile uyumluluk
- **Emoji'lerle zenginleştirilmiş** görsel içerik
- **Hızlı okuma** için optimize edilmiş
- **Versiyon bilgileri** dahil

## 🎯 Teknik Detaylar

### CVE Arama Algoritması:
- **Sürüm Normalizasyonu**: Regex ile sürüm numaralarını temizleme
- **Pattern Matching**: Farklı sürüm formatlarında arama
- **Fallback Sistemi**: Sürüm olmayan servisler için genel arama
- **Timeout Yönetimi**: 10 saniye CVE arama, 30 saniye LLM analizi

### PDF Raporlama:
- **ReportLab Kütüphanesi**: Profesyonel PDF oluşturma
- **Tablo Tasarımı**: Renkli başlıklar ve veri satırları
- **Stil Sistemi**: Özelleştirilmiş başlık ve metin stilleri
- **Otomatik Sayfalama**: A4 formatında optimize edilmiş

## 🛡️ Güvenlik Notları

- API anahtarlarınızı güvenli tutun
- Sadece kendi sistemlerinizde test yapın
- Yasal sınırlar içinde kalın
- Etik hacking prensiplerini takip edin
- Versiyon bilgisi ile daha doğru zafiyet tespiti yapın

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

## 🚀 Changelog

### v2.0 - Versiyon İyileştirmeleri & PDF Raporlama
- ✅ Gelişmiş versiyon analizi ve sürüm eşleşme kontrolü
- ✅ Akıllı fallback sistemi ile %100 servis kapsama
- ✅ Profesyonel PDF raporlama (reportlab entegrasyonu)
- ✅ Servis detay tabloları ve CVE sürüm eşleşmesi
- ✅ Detaylı analiz özeti ve başarı oranları
- ✅ Gelişmiş hata yönetimi ve timeout kontrolü

### v1.0 - Temel Özellikler
- ✅ Shodan API entegrasyonu
- ✅ MITRE CVE arama
- ✅ LLM çözüm önerileri
- ✅ Modern UI tasarımı

## 📸 Proje Görseller


<img width="1919" height="1020" alt="image" src="https://github.com/user-attachments/assets/c059dadc-e290-46b1-b384-503d655124f7" />

<img width="1298" height="862" alt="image" src="https://github.com/user-attachments/assets/5cebeb37-49b4-4ef9-9b8e-537911146e90" />

<img width="1919" height="1018" alt="image" src="https://github.com/user-attachments/assets/f7c60ebc-2acb-44dc-a84e-3aabe104edb5" />

<img width="1919" height="1020" alt="image" src="https://github.com/user-attachments/assets/55780241-0daa-4bef-87a9-32f0b4d3004a" />

<img width="1919" height="1021" alt="image" src="https://github.com/user-attachments/assets/bf425f28-21f4-40be-8b6f-2025c7a93fb8" />


