
from Api_Shodan import shodan_servisleri_al, nmap_ile_surumu_bul, shodan_port_sorgula, shodan_genel_arama
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup

load_dotenv()

def mitre_cve_ara(urun, surum):
    import requests
    import time
    
   
    timeout = 10  # 10 saniye timeout
    
    try:
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={urun} {surum}"
        yanit = requests.get(url, timeout=timeout)
        yanit.raise_for_status()  # HTTP hatalarını kontrol et
        
        soup = BeautifulSoup(yanit.text, "html.parser")
        cve_listesi = []
        
        # Sadece ilk 5 CVE'yi al (performans için)
        count = 0
        for satir in soup.find_all("tr")[1:]:
            if count >= 5:  # Maksimum 5 CVE
                break
                
            sutunlar = satir.find_all("td")
            if len(sutunlar) == 2:
                cve_id = sutunlar[0].text.strip()
                aciklama = sutunlar[1].text.strip()
                
                # Boş CVE'leri atla
                if cve_id and aciklama:
                    cve_listesi.append({"cve_id": cve_id, "aciklama": aciklama})
                    count += 1
        
        return cve_listesi
        
    except requests.exceptions.Timeout:
        print(f"⚠️ CVE arama zaman aşımına uğradı ({urun} {surum})")
        return []
    except requests.exceptions.RequestException as e:
        print(f"⚠️ CVE arama hatası ({urun} {surum}): {e}")
        return []
    except Exception as e:
        print(f"⚠️ CVE arama genel hatası ({urun} {surum}): {e}")
        return []

def llm_cozum_onerisi_getir(cve_aciklama):
    try:
        from LLM_Scanner import suggest_mitigation
        import time
        
        # Timeout kontrolü
        start_time = time.time()
        timeout = 30  # 30 saniye timeout
        
        result = suggest_mitigation(cve_aciklama)
        
        # Timeout kontrolü
        if time.time() - start_time > timeout:
            return "⚠️ LLM analizi zaman aşımına uğradı. Lütfen daha sonra tekrar deneyin."
        
        return result
        
    except ImportError:
        return "⚠️ LLM modülü bulunamadı. Groq API anahtarınızı kontrol edin."
    except Exception as e:
        return f"⚠️ LLM analizi hatası: {str(e)}"

def shodan_mitre_llm_analiz(ip_adresi):
    servisler = shodan_servisleri_al(ip_adresi)
    for servis in servisler:
        urun = servis["urun"]
        surum = servis["surum"]
        port = servis["port"]
        if not surum:
            print(f"{urun} için sürüm bulunamadı, nmap ile tespit ediliyor...")
            urun, surum = nmap_ile_surumu_bul(ip_adresi, port)
        if not urun or not surum:
            print(f"{port} için servis/sürüm tespit edilemedi.")
            continue
        print(f"\n {urun} {surum} için CVE aranıyor...")
        cve_listesi = mitre_cve_ara(urun, surum)
        if not cve_listesi:
            print(" CVE kaydı bulunamadı.")
            continue
        for cve in cve_listesi[:2]:
            print(f"\n CVE ID: {cve['cve_id']}")
            print(f" Açıklama: {cve['aciklama']}")
            ai_cevap = llm_cozum_onerisi_getir(cve['aciklama'])
            print(f"\n LLM Çözüm Önerisi:\n{ai_cevap}")
            print("-" * 60)

def shodan_ip_acik_portlari_goster(ip_adresi):
    servisler = shodan_servisleri_al(ip_adresi)
    if not servisler:
        print("Bu IP'de Shodan'da açık port veya servis kaydı yok.")
        return
    print(f"{ip_adresi} IP adresinde açık portlar ve servisler:")
    for servis in servisler:
        print(f"Port: {servis['port']} | Ürün: {servis['urun']} | Sürüm: {servis['surum']}")


