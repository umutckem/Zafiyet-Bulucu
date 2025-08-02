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
