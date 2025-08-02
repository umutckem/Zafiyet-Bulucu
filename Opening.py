
def Ust_Yazi():
    giris_yazisi = "| [3] Genel Arama (örn: apache, nginx, webcam, port:22 vb.) |"
    uzunluk = len(giris_yazisi)

    print("\n" + "*" * uzunluk)
    print("-" * uzunluk)
    print("| Zafiyet Bulucu Programına Hoş Geldiniz".ljust(uzunluk - 1) + "|")
    print("| Yapımcı: Umutcan Kemahlı".ljust(uzunluk - 1) + "|")
    print("-" * uzunluk)
    print("| Yapmak istediğiniz işlemi seçin".ljust(uzunluk - 1) + "|")
    print("-" * uzunluk)
    print("| [0] Çıkış".ljust(uzunluk - 1) + "|")
    print("| [1] IP Üzerinde Zafiyet Analizi".ljust(uzunluk - 1) + "|")
    print("| [2] IP Üzerinde Açık Port ve Servisleri Listele".ljust(uzunluk - 1) + "|")
    print(giris_yazisi)
    print("-" * uzunluk)
    print("*" * uzunluk + "\n")