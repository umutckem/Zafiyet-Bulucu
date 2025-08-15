import shodan
import os
from dotenv import load_dotenv
from shodan.exception import APIError
import subprocess
import socket

# Tüm socket işlemleri için global timeout (20 saniye)
socket.setdefaulttimeout(20)

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")
api = shodan.Shodan(API_KEY)

def shodan_servisleri_al(ip_adresi):
    # API anahtarı kontrolü
    if not API_KEY or API_KEY == "your_shodan_api_key_here":
        print("❌ Shodan API anahtarı bulunamadı!")
        print("📝 Lütfen .env dosyasında SHODAN_API_KEY değerini ayarlayın.")
        return []
    
    try:
        sonuc = api.host(ip_adresi)
        servisler = []
        for veri in sonuc.get("data", []):
            urun = veri.get("product")
            surum = veri.get("version")
            port = veri.get("port")
            if urun:
                servisler.append({"urun": urun, "surum": surum, "port": port})
        return servisler
    except socket.timeout:
        print("❌ Shodan IP sorgusu zaman aşımına uğradı (20 saniye).")
        print("💡 Lütfen ağı veya IP'yi kontrol edin.")
        return []
    except Exception as e:
        print(f"❌ Shodan IP sorgu hatası: {e}")
        print("🔧 IP adresini kontrol edin.")
        return []

def nmap_ile_surumu_bul(ip_adresi, port):
    try:
        sonuc = subprocess.run([
            "nmap", "-sV", "-p", str(port), ip_adresi
        ], capture_output=True, text=True)
        for satir in sonuc.stdout.splitlines():
            if "/tcp" in satir and "open" in satir:
                parcalar = satir.split()
                if len(parcalar) >= 4:
                    return parcalar[2], parcalar[3]  # urun, surum
    except Exception as e:
        print(f"nmap hatası: {e}")
    return None, None

def nmap_ile_servisleri_bul(ip_adresi, port_range="1-1000"):
    """Nmap ile hızlı servis tespiti yapar"""
    try:
        print(f"🔍 {ip_adresi} için nmap servis taraması başlatılıyor...")
        print(f"📡 Port aralığı: {port_range}")
        
        # Nmap komutu - hızlı tarama için optimize edilmiş
        komut = [
            "nmap", 
            "-sS",           # SYN scan (hızlı)
            "-sV",           # Versiyon tespiti
            "--version-intensity", "5",  # Orta yoğunluk
            "-p", port_range,  # Port aralığı
            "--max-retries", "1",  # Hızlı tarama
            ip_adresi
        ]
        
        sonuc = subprocess.run(komut, capture_output=True, text=True, timeout=60)
        
        if sonuc.returncode != 0:
            print(f"❌ Nmap tarama hatası: {sonuc.stderr}")
            return []
        
        servisler = []
        for satir in sonuc.stdout.splitlines():
            # Port açık ve servis bilgisi var mı?
            if "/tcp" in satir and "open" in satir:
                parcalar = satir.split()
                if len(parcalar) >= 4:
                    port = parcalar[0].split('/')[0]  # Port numarası
                    urun = parcalar[2]  # Ürün adı
                    surum = parcalar[3] if len(parcalar) > 3 else None
                    
                    # Sürüm bilgisini temizle
                    if surum and surum.startswith('('):
                        surum = None
                    
                    servisler.append({
                        "urun": urun,
                        "surum": surum,
                        "port": int(port)
                    })
                    
                    print(f"✅ Port {port}: {urun} {surum or 'Sürüm bilgisi yok'}")
        
        print(f"🎯 Toplam {len(servisler)} servis bulundu!")
        return servisler
        
    except subprocess.TimeoutExpired:
        print("❌ Nmap tarama zaman aşımına uğradı (60 saniye)")
        return []
    except FileNotFoundError:
        print("❌ Nmap bulunamadı! Lütfen nmap'i yükleyin.")
        print("💡 Windows: https://nmap.org/download.html")
        print("💡 Linux: sudo apt-get install nmap")
        return []
    except Exception as e:
        print(f"❌ Nmap tarama hatası: {e}")
        return []

def nmap_hizli_port_tarama(ip_adresi, port_range="1-1000"):
    """Sadece açık portları hızlıca tespit eder"""
    try:
        print(f"🔍 {ip_adresi} için hızlı port taraması başlatılıyor...")
        
        komut = [
            "nmap",
            "-sS",           # SYN scan
            "-p", port_range,
            "--max-retries", "1",
            ip_adresi
        ]
        
        sonuc = subprocess.run(komut, capture_output=True, text=True, timeout=30)
        
        if sonuc.returncode != 0:
            print(f"❌ Nmap port tarama hatası: {sonuc.stderr}")
            return []
        
        acik_portlar = []
        for satir in sonuc.stdout.splitlines():
            if "/tcp" in satir and "open" in satir:
                port = satir.split('/')[0]
                acik_portlar.append(int(port))
                print(f"✅ Port {port} açık")
        
        print(f"🎯 Toplam {len(acik_portlar)} açık port bulundu!")
        return acik_portlar
        
    except subprocess.TimeoutExpired:
        print("❌ Nmap port tarama zaman aşımına uğradı (30 saniye)")
        return []
    except FileNotFoundError:
        print("❌ Nmap bulunamadı! Lütfen nmap'i yükleyin.")
        return []
    except Exception as e:
        print(f"❌ Nmap port tarama hatası: {e}")
        return []

def shodan_port_sorgula(ip_adresi, port):
    # API anahtarı kontrolü
    if not API_KEY or API_KEY == "your_shodan_api_key_here":
        print("❌ Shodan API anahtarı bulunamadı!")
        print("📝 Lütfen .env dosyasında SHODAN_API_KEY değerini ayarlayın.")
        return
    
    try:
        print(f"Shodan'da {ip_adresi} IP'sinde {port} portu sorgulanıyor...")
        sonuc = api.host(ip_adresi)
        port = int(port)
        bulundu = False
        for veri in sonuc.get("data", []):
            if veri.get("port") == port:
                print(f"Port: {port} | Durum: Açık | Ürün: {veri.get('product', 'Bilinmiyor')} | Sürüm: {veri.get('version', 'Bilinmiyor')}")
                bulundu = True
        if not bulundu:
            print(f"Port {port} bu IP'de açık değil veya Shodan'da kayıtlı değil.")
    except socket.timeout:
        print("❌ Shodan port sorgusu zaman aşımına uğradı (20 saniye).")
        print("💡 Lütfen ağı veya IP'yi kontrol edin.")
    except Exception as e:
        print(f"❌ Shodan port sorgu hatası: {e}")
        print("🔧 IP adresini ve portu kontrol edin.")

def shodan_genel_arama(anahtar_kelime):
    # API anahtarı kontrolü
    if not API_KEY or API_KEY == "your_shodan_api_key_here":
        print("❌ Shodan API anahtarı bulunamadı!")
        print("📝 Lütfen .env dosyasında SHODAN_API_KEY değerini ayarlayın.")
        print("🔗 https://account.shodan.io/register adresinden ücretsiz hesap oluşturun.")
        return
    
    try:
        print(f"Shodan'da '{anahtar_kelime}' için arama yapılıyor...\n")
        sonuc = api.search(anahtar_kelime, limit=20)  # Limit ekledim
        toplam = sonuc.get('total', 0)
        print(f"Toplam sonuç: {toplam} (İlk 20 sonuç gösteriliyor)\n")
        
        if not sonuc.get('matches'):
            print("❌ Arama sonucu bulunamadı.")
            print("💡 Farklı bir arama terimi deneyin.")
            return
        
        for i, kayit in enumerate(sonuc['matches']):
            ip = kayit.get('ip_str', 'N/A')
            port = kayit.get('port', 'N/A')
            urun = kayit.get('product', 'N/A')
            surum = kayit.get('version', 'N/A')
            
            # Ülke bilgisi
            location = kayit.get('location', {})
            country = location.get('country_name', 'Bilinmiyor')
            city = location.get('city', 'Bilinmiyor')
            
            # Port bilgisi - mevcut portu kullan
            port_info = str(port) if port != 'N/A' else 'Bilinmiyor'
            
            print(f"{i+1}. IP: {ip}")
            print(f"   🌍 Ülke: {country} | Şehir: {city}")
            print(f"   🔍 Ürün: {urun} | Sürüm: {surum}")
            print(f"   🌐 Port: {port_info}")
            
            # Ek bilgiler varsa göster
            if kayit.get('data'):
                print(f"   📋 Veri: {kayit['data'][:100]}...")
            
            print("-" * 60)
            
    except socket.timeout:
        print("❌ Shodan genel arama zaman aşımına uğradı (20 saniye).")
        print("💡 Lütfen ağı veya sorguyu kontrol edin.")
    except Exception as e:
        print(f"❌ Shodan genel arama hatası: {e}")
        print("🔧 API anahtarınızı kontrol edin ve internet bağlantınızı test edin.")
        print("📝 .env dosyasında SHODAN_API_KEY değerinin doğru olduğundan emin olun.")
