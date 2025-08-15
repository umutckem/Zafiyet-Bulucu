
from Api_Shodan import shodan_servisleri_al, nmap_ile_surumu_bul, shodan_port_sorgula, shodan_genel_arama
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup

load_dotenv()

def mitre_cve_ara(urun, surum):
    import requests
    import time
    import re
    
    timeout = 10  # 10 saniye timeout
    
    try:
        # Versiyon bilgisini temizle ve normalize et
        if surum:
            # Sürüm numarasını temizle (örn: "1.2.3" -> "1.2.3", "v1.2.3" -> "1.2.3")
            clean_version = re.sub(r'^[vV]', '', surum.strip())
            # Sadece sayısal sürüm bilgisi varsa kullan
            if re.match(r'^\d+\.\d+', clean_version):
                search_query = f"{urun} {clean_version}"
            else:
                search_query = f"{urun} {surum}"
        else:
            search_query = urun
        
        print(f"🔍 CVE arama sorgusu: '{search_query}'")
        
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={search_query}"
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
                    # Sürüm bilgisini CVE açıklamasında ara
                    version_match = False
                    if surum:
                        # Farklı sürüm formatlarını kontrol et
                        version_patterns = [
                            surum,
                            surum.replace('.', ' '),
                            surum.replace('.', ''),
                            f"version {surum}",
                            f"v{surum}"
                        ]
                        
                        for pattern in version_patterns:
                            if pattern.lower() in aciklama.lower():
                                version_match = True
                                break
                    
                    cve_listesi.append({
                        "cve_id": cve_id, 
                        "aciklama": aciklama,
                        "version_match": version_match,
                        "search_query": search_query
                    })
                    count += 1
        
        if not cve_listesi:
            print(f"⚠️ '{search_query}' için CVE bulunamadı. Sürüm bilgisi olmadan tekrar deneniyor...")
            # Sürüm bilgisi olmadan tekrar dene
            if surum:
                url_fallback = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={urun}"
                yanit_fallback = requests.get(url_fallback, timeout=timeout)
                yanit_fallback.raise_for_status()
                
                soup_fallback = BeautifulSoup(yanit_fallback.text, "html.parser")
                count_fallback = 0
                
                for satir in soup_fallback.find_all("tr")[1:]:
                    if count_fallback >= 3:  # Fallback için sadece 3 CVE
                        break
                        
                    sutunlar = satir.find_all("td")
                    if len(sutunlar) == 2:
                        cve_id = sutunlar[0].text.strip()
                        aciklama = sutunlar[1].text.strip()
                        
                        if cve_id and aciklama:
                            cve_listesi.append({
                                "cve_id": cve_id, 
                                "aciklama": aciklama,
                                "version_match": False,
                                "search_query": f"{urun} (sürüm bilgisi olmadan)"
                            })
                            count_fallback += 1
        
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
    if not servisler:
        print(f"❌ {ip_adresi} için Shodan'da servis bulunamadı.")
        print("💡 Nmap ile servis tespiti deneniyor...")
        
        # Nmap ile servis tespiti
        from Api_Shodan import nmap_ile_servisleri_bul
        servisler = nmap_ile_servisleri_bul(ip_adresi)
        
        if not servisler:
            print(f"❌ {ip_adresi} için hiçbir servis tespit edilemedi.")
            return
    
    print(f"\n🎯 {ip_adresi} IP adresinde {len(servisler)} servis bulundu:")
    for i, servis in enumerate(servisler, 1):
        print(f"  {i}. Port {servis['port']}: {servis['urun']} {servis['surum'] or 'Sürüm bilgisi yok'}")
    
    print(f"\n🔍 CVE analizi başlatılıyor...")
    print("=" * 80)
    
    analyzed_services = 0
    skipped_services = 0
    total_cves = 0
    
    for i, servis in enumerate(servisler, 1):
        urun = servis["urun"]
        surum = servis["surum"]
        port = servis["port"]
        
        print(f"\n📡 Servis {i}/{len(servisler)}: {urun} (Port: {port})")
        
        # Sürüm bilgisi kontrolü
        if not surum:
            print(f"⚠️ {urun} için sürüm bulunamadı, nmap ile tespit ediliyor...")
            urun, surum = nmap_ile_surumu_bul(ip_adresi, port)
            
            if not urun or not surum:
                print(f"❌ {port} portu için servis/sürüm tespit edilemedi.")
                skipped_services += 1
                continue
        
        print(f"✅ Sürüm tespit edildi: {urun} {surum}")
        print(f"🔍 CVE aranıyor...")
        
        cve_listesi = mitre_cve_ara(urun, surum)
        
        if not cve_listesi:
            print(f"⚠️ {urun} {surum} için CVE kaydı bulunamadı.")
            skipped_services += 1
            continue
        
        print(f"🎯 {len(cve_listesi)} CVE bulundu!")
        analyzed_services += 1
        total_cves += len(cve_listesi)
        
        # CVE'leri göster
        for j, cve in enumerate(cve_listesi[:3], 1):  # En fazla 3 CVE göster
            print(f"\n📋 CVE {j}: {cve['cve_id']}")
            print(f"📝 Açıklama: {cve['aciklama']}")
            
            # Sürüm eşleşmesi varsa vurgula
            if cve.get('version_match'):
                print(f"✅ Sürüm eşleşmesi: {surum}")
            else:
                print(f"⚠️ Sürüm eşleşmesi belirsiz")
            
            # LLM çözüm önerisi
            print(f"🤖 LLM çözüm önerisi alınıyor...")
            ai_cevap = llm_cozum_onerisi_getir(cve['aciklama'])
            print(f"💡 Çözüm Önerisi:\n{ai_cevap}")
            print("-" * 60)
        
        if len(cve_listesi) > 3:
            print(f"📊 ... ve {len(cve_listesi) - 3} CVE daha bulundu.")
    
    # Özet rapor
    print(f"\n" + "=" * 80)
    print(f"📊 ANALİZ ÖZETİ")
    print(f"🎯 Toplam servis: {len(servisler)}")
    print(f"✅ Analiz edilen: {analyzed_services}")
    print(f"⚠️ Atlanan (sürüm yok): {skipped_services}")
    print(f"🔍 Toplam CVE: {total_cves}")
    print(f"📈 Başarı oranı: {(analyzed_services/len(servisler)*100):.1f}%")
    print("=" * 80)

def shodan_ip_acik_portlari_goster(ip_adresi):
    servisler = shodan_servisleri_al(ip_adresi)
    if not servisler:
        print("Bu IP'de Shodan'da açık port veya servis kaydı yok.")
        return
    print(f"{ip_adresi} IP adresinde açık portlar ve servisler:")
    for servis in servisler:
        print(f"Port: {servis['port']} | Ürün: {servis['urun']} | Sürüm: {servis['surum']}")


