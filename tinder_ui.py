import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from Api_Shodan import shodan_servisleri_al, nmap_ile_surumu_bul, nmap_ile_servisleri_bul, nmap_hizli_port_tarama, shodan_port_sorgula, shodan_genel_arama
from Main import mitre_cve_ara, llm_cozum_onerisi_getir, shodan_mitre_llm_analiz, shodan_ip_acik_portlari_goster
from output_capture import OutputCapture
import re

# PDF oluşturma için gerekli importlar
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

def sanitize_for_pdf(text: str) -> str:
	"""PDF için metni güvenli hale getirir: emoji ve problemli Unicodeları temizler, Türkçe karakterleri ASCII'ye dönüştürür."""
	if not isinstance(text, str):
		return text
	# Türkçe karakter dönüşümü
	translations = str.maketrans({
		'ç':'c','Ç':'C','ğ':'g','Ğ':'G','ı':'i','İ':'I','ö':'o','Ö':'O','ş':'s','Ş':'S','ü':'u','Ü':'U'
	})
	clean = text.translate(translations)
	# Emoji ve BMP dışı karakterleri kaldır
	clean = re.sub(r"[\U00010000-\U0010FFFF]", "", clean)
	# Kontrol edilemeyen diğer semboller yerine boşluk
	clean = re.sub(r"[\u0000-\u001F]", " ", clean)
	return clean

class ModernUI:
    def __init__(self, root):
        self.root = root
        self.root.title(" Zafiyet Bulucu Pro")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1a1a2e")
        
  
        self.output_capture = OutputCapture()
        
      
        self.current_analysis_result = ""
        self.found_services = []
        self.cve_results = {}
        self.open_ports = []
        self.llm_analysis_results = ""  # LLM sonuçları için ayrı değişken
        
     
        self.colors = {
            'bg_dark': '#1a1a2e',
            'bg_card': '#16213e',
            'bg_input': '#0f3460',
            'primary': '#e94560',
            'secondary': '#533483',
            'accent': '#00d4ff',
            'success': '#00ff88',
            'warning': '#ffaa00',
            'danger': '#ff4757',
            'text_light': '#ffffff',
            'text_gray': '#a0a0a0',
            'border': '#2d3748',
            'cve_highlight': '#ff6b6b',
            'llm_highlight': '#4ecdc4',
            'ai_highlight': '#45b7d1'
        }
        
        self.setup_ui()
        
    def setup_ui(self):
      
        main_frame = tk.Frame(self.root, bg=self.colors['bg_dark'])
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)
        
       
        title_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        title_frame.pack(fill='x', pady=(0, 30))
        
        title_label = tk.Label(
            title_frame,
            text=" Zafiyet Bulucu Pro",
            font=("Segoe UI", 28, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['bg_dark']
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Güvenlik Analizi & Zafiyet Tespiti",
            font=("Segoe UI", 14),
            fg=self.colors['text_gray'],
            bg=self.colors['bg_dark']
        )
        subtitle_label.pack(pady=(5, 0))
        
    
        self.card_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        self.card_frame.pack(fill='both', expand=True)
        
      
        self.show_main_menu_card()
        
    def create_rounded_button(self, parent, text, command, color='primary', size='normal'):
        """Modern yuvarlak köşeli buton oluşturur"""
        btn = tk.Button(
            parent,
            text=text,
            font=("Segoe UI", 12 if size == 'normal' else 14, "bold"),
            bg=self.colors[color],
            fg=self.colors['text_light'],
            relief='flat',
            padx=25,
            pady=12,
            command=command,
            cursor='hand2'
        )
        btn.bind('<Enter>', lambda e, b=btn, c=color: self.on_button_hover(b, c, True))
        btn.bind('<Leave>', lambda e, b=btn, c=color: self.on_button_hover(b, c, False))
        return btn
        
    def on_button_hover(self, button, color, entering):
        if entering:
            button.configure(bg=self.colors['accent'])
        else:
            button.configure(bg=self.colors[color])
            
    def show_main_menu_card(self):
    
        for widget in self.card_frame.winfo_children():
            widget.destroy()
            
     
        card = tk.Frame(
            self.card_frame,
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0
        )
        card.pack(fill='both', expand=True, padx=20, pady=20)
        
     
        card_title = tk.Label(
            card,
            text=" Analiz Seçenekleri",
            font=("Segoe UI", 22, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        card_title.pack(pady=(30, 40))
        
       
        button_frame = tk.Frame(card, bg=self.colors['bg_card'])
        button_frame.pack(fill='both', expand=True, padx=80, pady=40)
        
        # Butonlar (açıklama metinleri ile)
        button_info = [
            ("🔍 IP Zafiyet Analizi", self.show_ip_analysis_card, 'primary', "Shodan, Nmap ve CVE analizi"),
            ("⚡ Hızlı Nmap Tarama", self.show_nmap_scan_card, 'secondary', "Port ve servis tespiti"),
            ("📡 Açık Port Taraması", self.show_port_list_card, 'accent', "Hedef IP açık portlar"),
            ("🔎 Shodan Arama", self.show_general_search_card, 'warning', "Genel arama ve keşif")
        ]
        
        for i, (text, command, color, desc) in enumerate(button_info):
            row = i // 2
            col = i % 2
            tile = tk.Frame(button_frame, bg=self.colors['bg_card'])
            tile.grid(row=row, column=col, padx=20, pady=15, sticky='ew')
            btn = self.create_rounded_button(tile, text, command, color)
            btn.pack(fill='x')
            tk.Label(
                tile,
                text=desc,
                font=("Segoe UI", 10),
                fg=self.colors['text_gray'],
                bg=self.colors['bg_card']
            ).pack(pady=(6, 0))
        
        # Sütun esnekliği
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
            
    def show_ip_analysis_card(self):
        """IP zafiyet analizi kartını göster"""
        for widget in self.card_frame.winfo_children():
            widget.destroy()
            
        # Ana kart
        card = tk.Frame(
            self.card_frame,
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0
        )
        card.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Üst bar
        top_bar = tk.Frame(card, bg=self.colors['bg_card'])
        top_bar.pack(fill='x', padx=20, pady=20)
        
        # Geri butonu
        back_btn = self.create_rounded_button(
            top_bar, "← Geri", self.show_main_menu_card, 'warning', 'small'
        )
        back_btn.pack(side='left')
        
        # Başlık
        title = tk.Label(
            top_bar,
            text=" IP Zafiyet Analizi",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='right')
        
        # Sol panel
        left_panel = tk.Frame(card, bg=self.colors['bg_card'])
        left_panel.pack(side='left', fill='y', padx=(40, 20), pady=30)
        
        # IP girişi
        input_label = tk.Label(
            left_panel,
            text="IP Adresi:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        input_label.pack(anchor='w', pady=(0, 10))
        
        # Input container
        input_container = tk.Frame(left_panel, bg=self.colors['bg_input'], relief='flat', bd=0)
        input_container.pack(fill='x', pady=(0, 20))
        
        self.ip_entry = tk.Entry(
            input_container,
            font=("Consolas", 14),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light']
        )
        self.ip_entry.pack(fill='x', padx=15, pady=15)
        
        # Buton container
        button_container = tk.Frame(left_panel, bg=self.colors['bg_card'])
        button_container.pack(fill='x', pady=20)
        
        # Servisleri bul butonu (ana analiz butonu)
        analyze_btn = self.create_rounded_button(
            button_container, "🔍 Servisleri Bul & CVE Analizi", self.find_services_and_cve, 'success'
        )
        analyze_btn.pack(fill='x', pady=(0, 10))
        
        # LLM analizi butonu
        llm_btn = self.create_rounded_button(
            button_container, "🤖 LLM Çözüm Önerisi", self.show_llm_analysis_window, 'primary'
        )
        llm_btn.pack(fill='x', pady=(0, 10))
        
        # Sonucu kaydet butonu
        save_btn = self.create_rounded_button(
            button_container, "💾 Sonucu Kaydet", self.save_analysis_result, 'accent'
        )
        save_btn.pack(fill='x')
        
        # Sağ panel
        right_panel = tk.Frame(card, bg=self.colors['bg_card'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(20, 40), pady=30)
        
        result_label = tk.Label(
            right_panel,
            text=" Analiz Sonuçları:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        result_label.pack(anchor='w', pady=(0, 10))
        
        # Sonuç text alanı
        self.result_text = scrolledtext.ScrolledText(
            right_panel,
            height=25,
            font=("Consolas", 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light'],
            selectbackground=self.colors['primary']
        )
        self.result_text.pack(fill='both', expand=True)
        
    def find_services_and_cve(self):
        """IP'deki servisleri bul ve CVE analizi yap"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_complete_analysis():
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"🔍 {ip} için kapsamlı analiz başlatılıyor...\n")
            self.result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            # Analiz sonuçlarını temizle
            self.current_analysis_result = ""
            self.llm_analysis_results = ""
            
            try:
                # 1. Adım: Shodan'dan servisleri al
                self.result_text.insert(tk.END, "📡 Shodan'dan servis bilgileri alınıyor...\n")
                self.found_services = shodan_servisleri_al(ip)
                
                if not self.found_services:
                    self.result_text.insert(tk.END, "❌ Bu IP'de Shodan'da servis kaydı bulunamadı.\n")
                    self.result_text.insert(tk.END, "💡 IP adresini kontrol edin veya farklı bir IP deneyin.\n")
                    return
                
                self.result_text.insert(tk.END, f"✅ {len(self.found_services)} servis bulundu!\n\n")
                
                # 2. Adım: Her servis için sürüm kontrolü ve CVE analizi
                total_cves = 0
                self.cve_results = {}
                all_cves = []
                analyzed_services = 0
                skipped_services = 0
                
                total_services = len(self.found_services)
                
                for i, service in enumerate(self.found_services, 1):
                    urun = service['urun']
                    surum = service['surum']
                    port = service['port']
                    
                    self.result_text.insert(tk.END, f"🔍 [{i}/{total_services}] {urun} (Port: {port})\n")
                    self.root.update()
                    
                    # Sürüm kontrolü
                    if not surum:
                        self.result_text.insert(tk.END, f"   🔧 Sürüm tespit ediliyor (nmap)...\n")
                        urun, surum = nmap_ile_surumu_bul(ip, port)
                    
                    if not urun or not surum:
                        self.result_text.insert(tk.END, f"   ⚠️ Sürüm tespit edilemedi - CVE analizi atlanıyor.\n\n")
                        skipped_services += 1
                        continue
                    
                    self.result_text.insert(tk.END, f"   📋 Sürüm: {surum}\n")
                    analyzed_services += 1
                    
                    # CVE analizi
                    self.result_text.insert(tk.END, f"   🔍 CVE kayıtları aranıyor...\n")
                    cve_listesi = mitre_cve_ara(urun, surum)
                    
                    if cve_listesi:
                        self.result_text.insert(tk.END, f"   ✅ {len(cve_listesi)} CVE bulundu!\n")
                        total_cves += len(cve_listesi)
                        self.cve_results[f"{urun}_{surum}"] = cve_listesi
                        
                        # CVE'leri listeye ekle
                        for cve in cve_listesi:
                            all_cves.append({
                                'cve': cve,
                                'service': f"{urun} {surum}",
                                'port': port
                            })
                        
                        # İlk 3 CVE'yi göster
                        for j, cve in enumerate(cve_listesi[:3], 1):
                            self.result_text.insert(tk.END, f"      {j}. {cve['cve_id']}: {cve['aciklama'][:80]}...\n")
                        
                        if len(cve_listesi) > 3:
                            self.result_text.insert(tk.END, f"      ... ve {len(cve_listesi) - 3} CVE daha\n")
                    else:
                        self.result_text.insert(tk.END, f"   ❌ CVE kaydı bulunamadı.\n")
                    
                    self.result_text.insert(tk.END, "\n")
                    
                    # Kısa bekleme
                    if i < total_services:
                        self.root.update()
                        import time
                        time.sleep(0.2)
                
                self.result_text.insert(tk.END, f"🎯 Analiz tamamlandı!\n")
                self.result_text.insert(tk.END, f"📊 Özet:\n")
                self.result_text.insert(tk.END, f"   • Toplam Servis: {len(self.found_services)}\n")
                self.result_text.insert(tk.END, f"   • Analiz Edilen: {analyzed_services}\n")
                self.result_text.insert(tk.END, f"   • Atlanan (Sürüm Yok): {skipped_services}\n")
                self.result_text.insert(tk.END, f"   • Bulunan CVE: {total_cves}\n\n")
                
                # CVE analiz sonuçlarını sakla
                self.current_analysis_result = f"🔍 IP Adresi: {ip}\n"
                self.current_analysis_result += f"📡 Toplam Servis Sayısı: {len(self.found_services)}\n"
                self.current_analysis_result += f"🔧 Analiz Edilen Servis: {analyzed_services}\n"
                self.current_analysis_result += f"⚠️ Atlanan Servis (Sürüm Yok): {skipped_services}\n"
                self.current_analysis_result += f"🎯 Bulunan CVE Sayısı: {total_cves}\n"
                self.current_analysis_result += "=" * 60 + "\n\n"
                
                if self.cve_results:
                    for service_key, cve_list in self.cve_results.items():
                        self.current_analysis_result += f"📋 Servis: {service_key.replace('_', ' ')}\n"
                        for cve in cve_list:
                            self.current_analysis_result += f"  🔍 {cve['cve_id']}: {cve['aciklama']}\n"
                        self.current_analysis_result += "\n"
                else:
                    self.current_analysis_result += "❌ Analiz edilebilir servis bulunamadı (sürüm bilgisi gerekli).\n\n"
                
                if all_cves:
                    self.result_text.insert(tk.END, "🤖 LLM çözüm önerileri için 'LLM Çözüm Önerisi' butonuna tıklayın.\n")
                    self.result_text.insert(tk.END, "=" * 80 + "\n\n")
                    self.root.update()
                    
                    # CVE seçim arayüzünü oluştur
                    self.create_cve_selection_interface(all_cves)
                else:
                    self.result_text.insert(tk.END, "⚠️ LLM analizi için CVE bulunamadı.\n")
                
            except Exception as e:
                self.result_text.insert(tk.END, f"\n❌ Hata: {str(e)}\n")
                
        threading.Thread(target=run_complete_analysis, daemon=True).start()
        
    def show_llm_analysis_window(self):
        """LLM çözüm önerisi için ayrı pencere aç"""
        if not hasattr(self, 'cve_results') or not self.cve_results:
            messagebox.showwarning("⚠️ Uyarı", "LLM analizi için CVE bulunamadı!\n\nÖnce '🔍 Servisleri Bul & CVE Analizi' butonuna tıklayarak analiz yapın.\n\nNot: Sadece sürüm bilgisi olan servisler için CVE analizi yapılır.")
            return
            
        # Yeni pencere oluştur
        llm_window = tk.Toplevel(self.root)
        llm_window.title("🤖 LLM Çözüm Önerisi")
        llm_window.geometry("1000x700")
        llm_window.configure(bg=self.colors['bg_dark'])
        llm_window.resizable(True, True)
        
        # Pencereyi ortala
        self.center_window(llm_window)
        
        # Ana frame
        main_frame = tk.Frame(llm_window, bg=self.colors['bg_dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Başlık
        title_label = tk.Label(
            main_frame,
            text="🤖 LLM Çözüm Önerisi",
            font=("Segoe UI", 18, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['bg_dark']
        )
        title_label.pack(pady=(0, 20))
        
        # CVE listesi frame
        list_frame = tk.Frame(main_frame, bg=self.colors['bg_card'])
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # CVE listesi başlığı
        list_title = tk.Label(
            list_frame,
            text="📋 Bulunan CVE'ler:",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        list_title.pack(anchor='w', padx=15, pady=(15, 10))
        
        # CVE listesi (Treeview)
        tree_frame = tk.Frame(list_frame, bg=self.colors['bg_card'])
        tree_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        # Treeview
        self.llm_cve_tree = ttk.Treeview(
            tree_frame,
            columns=('cve_id', 'service', 'port', 'description'),
            show='headings',
            yscrollcommand=scrollbar.set,
            selectmode='extended',
            style='Custom.Treeview'
        )
        scrollbar.config(command=self.llm_cve_tree.yview)
        
        # Sütun başlıkları
        self.llm_cve_tree.heading('cve_id', text='CVE ID', anchor='w')
        self.llm_cve_tree.heading('service', text='Servis', anchor='w')
        self.llm_cve_tree.heading('port', text='Port', anchor='w')
        self.llm_cve_tree.heading('description', text='Açıklama', anchor='w')
        
        # Sütun genişlikleri
        self.llm_cve_tree.column('cve_id', width=120, anchor='w')
        self.llm_cve_tree.column('service', width=150, anchor='w')
        self.llm_cve_tree.column('port', width=60, anchor='center')
        self.llm_cve_tree.column('description', width=400, anchor='w')
        
        self.llm_cve_tree.pack(fill='both', expand=True)
        
        # Treeview stilini ayarla
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Custom.Treeview', 
                      background=self.colors['bg_input'],
                      foreground=self.colors['text_light'],
                      fieldbackground=self.colors['bg_input'],
                      borderwidth=0)
        style.configure('Custom.Treeview.Heading', 
                      background=self.colors['secondary'],
                      foreground=self.colors['text_light'],
                      relief='flat',
                      font=('Segoe UI', 10, 'bold'))
        style.map('Custom.Treeview', 
                 background=[('selected', self.colors['primary'])],
                 foreground=[('selected', 'white')])
        
        # CVE'leri listeye ekle
        all_cves = []
        for service_key, cve_list in self.cve_results.items():
            for cve in cve_list:
                all_cves.append({
                    'cve': cve,
                    'service': service_key.replace('_', ' '),
                    'port': 'N/A'  # Port bilgisi servis anahtarında yok
                })
        
        self.llm_cve_vars = {}
        for i, cve_data in enumerate(all_cves):
            cve = cve_data['cve']
            service = cve_data['service']
            port = cve_data['port']
            
            # Kısa açıklama
            short_desc = (cve['aciklama'][:97] + '...') if len(cve['aciklama']) > 100 else cve['aciklama']
            
            # Treeview'a ekle
            item_id = self.llm_cve_tree.insert('', 'end', 
                                             values=(cve['cve_id'], service, port, short_desc),
                                             tags=('clickable',))
            
            # CVE verilerini sakla
            self.llm_cve_vars[item_id] = {
                'cve': cve,
                'selected': False
            }
        
        # Çift tıklama olayı
        self.llm_cve_tree.tag_bind('clickable', '<Double-1>', self.on_llm_cve_double_click)
        
        # Buton frame
        button_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        button_frame.pack(fill='x', pady=(20, 0))
        
        # Butonlar
        select_all_btn = tk.Button(
            button_frame,
            text="✓ Tümünü Seç",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            padx=15,
            pady=8,
            command=self.select_all_llm_cves
        )
        select_all_btn.pack(side='left', padx=5)
        
        deselect_all_btn = tk.Button(
            button_frame,
            text="✗ Seçimi Kaldır",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['danger'],
            fg='white',
            relief='flat',
            padx=15,
            pady=8,
            command=self.deselect_all_llm_cves
        )
        deselect_all_btn.pack(side='left', padx=5)
        
        analyze_btn = tk.Button(
            button_frame,
            text="🤖 Seçilenler için LLM Analizi",
            font=("Segoe UI", 12, "bold"),
            bg=self.colors['primary'],
            fg='white',
            relief='flat',
            padx=20,
            pady=10,
            command=lambda: self.analyze_selected_llm_cves(llm_window)
        )
        analyze_btn.pack(side='right', padx=5)
        
    def on_llm_cve_double_click(self, event):
        """LLM penceresinde CVE'ye çift tıklandığında"""
        item = self.llm_cve_tree.selection()[0]
        cve_data = self.llm_cve_vars[item]['cve']
        
        # Detay penceresi
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"CVE Detay: {cve_data['cve_id']}")
        detail_window.geometry("600x400")
        detail_window.configure(bg=self.colors['bg_dark'])
        detail_window.resizable(True, True)
        
        # Başlık
        title_frame = tk.Frame(detail_window, bg=self.colors['bg_dark'])
        title_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text=f"📋 {cve_data['cve_id']} Detayları",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['bg_dark']
        )
        title_label.pack(side='left')
        
        # İçerik
        content_frame = tk.Frame(detail_window, bg=self.colors['bg_card'])
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Detay text
        detail_text = scrolledtext.ScrolledText(
            content_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            padx=10,
            pady=10
        )
        detail_text.pack(fill='both', expand=True)
        
        # CVE bilgilerini ekle
        detail_text.insert(tk.END, f"🔍 CVE ID: {cve_data['cve_id']}\n\n")
        detail_text.insert(tk.END, f"📝 Açıklama:\n{cve_data['aciklama']}\n\n")
        
        # Pencereyi ortala
        self.center_window(detail_window)
        
    def select_all_llm_cves(self):
        """LLM penceresinde tüm CVE'leri seç"""
        for item in self.llm_cve_tree.get_children():
            self.llm_cve_tree.selection_add(item)
            self.llm_cve_vars[item]['selected'] = True
    
    def deselect_all_llm_cves(self):
        """LLM penceresinde tüm CVE seçimlerini kaldır"""
        self.llm_cve_tree.selection_remove(self.llm_cve_tree.get_children())
        for item in self.llm_cve_vars:
            self.llm_cve_vars[item]['selected'] = False
    
    def analyze_selected_llm_cves(self, llm_window):
        """LLM penceresinde seçilen CVE'ler için analiz yap"""
        selected_items = self.llm_cve_tree.selection()
        
        if not selected_items:
            messagebox.showwarning("Uyarı", "Lütfen en az bir CVE seçin!")
            return
        
        selected_cves = []
        for item in selected_items:
            selected_cves.append(self.llm_cve_vars[item]['cve'])
            self.llm_cve_vars[item]['selected'] = True
        
        # LLM analizi için yeni pencere aç
        self.show_llm_analysis_results(selected_cves, llm_window)
        
    def show_llm_analysis_results(self, selected_cves, parent_window):
        """LLM analiz sonuçlarını göster"""
        # Sonuç penceresi
        result_window = tk.Toplevel(parent_window)
        result_window.title("🤖 LLM Analiz Sonuçları")
        result_window.geometry("1200x800")
        result_window.configure(bg=self.colors['bg_dark'])
        result_window.resizable(True, True)
        
        # Pencereyi ortala
        self.center_window(result_window)
        
        # Ana frame
        main_frame = tk.Frame(result_window, bg=self.colors['bg_dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Başlık
        title_label = tk.Label(
            main_frame,
            text=f"🤖 LLM Analiz Sonuçları ({len(selected_cves)} CVE)",
            font=("Segoe UI", 16, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['bg_dark']
        )
        title_label.pack(pady=(0, 20))
        
        # Sonuç text alanı
        result_text = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            padx=15,
            pady=15
        )
        result_text.pack(fill='both', expand=True)
        
        # Kaydet butonu frame
        save_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        save_frame.pack(fill='x', pady=(20, 0))
        
        # Kaydet butonu
        save_btn = tk.Button(
            save_frame,
            text="💾 Bu Sonuçları Kaydet",
            font=("Segoe UI", 12, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            padx=20,
            pady=10,
            command=lambda: self.save_llm_results_to_file(result_text.get(1.0, tk.END), selected_cves)
        )
        save_btn.pack(side='right', padx=5)
        
        # Analiz başlat
        def run_llm_analysis():
            result_text.insert(tk.END, f"🤖 {len(selected_cves)} CVE için LLM analizi başlatılıyor...\n")
            result_text.insert(tk.END, "=" * 80 + "\n\n")
            result_window.update()
            
            # LLM sonuçlarını saklamak için geçici değişken
            llm_results = ""
            
            try:
                for i, cve in enumerate(selected_cves, 1):
                    result_text.insert(tk.END, f"📋 [{i}/{len(selected_cves)}] {cve['cve_id']} analiz ediliyor...\n")
                    result_window.update()
                    
                    try:
                        # LLM çözüm önerisi al
                        llm_solution = llm_cozum_onerisi_getir(cve['aciklama'])
                        
                        result_text.insert(tk.END, f"\n🔍 CVE ID: {cve['cve_id']}\n")
                        result_text.insert(tk.END, f"📝 Açıklama: {cve['aciklama']}\n")
                        result_text.insert(tk.END, "=" * 60 + "\n")
                        result_text.insert(tk.END, f"🤖 LLM Çözüm Önerisi:\n{llm_solution}\n")
                        result_text.insert(tk.END, "=" * 60 + "\n\n")
                        
                        # Sonucu geçici değişkende sakla
                        llm_results += f"\n🔍 CVE ID: {cve['cve_id']}\n"
                        llm_results += f"📝 Açıklama: {cve['aciklama']}\n"
                        llm_results += f"🤖 LLM Çözüm Önerisi:\n{llm_solution}\n"
                        llm_results += "=" * 60 + "\n\n"
                        
                    except Exception as e:
                        result_text.insert(tk.END, f"❌ {cve['cve_id']} için LLM analizi hatası: {str(e)}\n\n")
                        continue
                    
                    # Her 2 CVE'de bir kısa bekleme
                    if i % 2 == 0:
                        result_text.insert(tk.END, "⏳ Kısa bir bekleme...\n")
                        result_window.update()
                        import time
                        time.sleep(0.5)
                
                result_text.insert(tk.END, f"✅ Seçilen CVE'ler için LLM analizi tamamlandı!\n")
                result_text.insert(tk.END, f"💾 Sonuçları kaydetmek için 'Bu Sonuçları Kaydet' butonuna tıklayın.\n")
                
                # LLM sonuçlarını ana pencereye aktar
                self.current_analysis_result = llm_results
                
            except Exception as e:
                result_text.insert(tk.END, f"\n❌ LLM analizi genel hatası: {str(e)}\n")
        
        threading.Thread(target=run_llm_analysis, daemon=True).start()
        
    def create_cve_selection_interface(self, all_cves):
        """Modern CVE seçim arayüzü - Genişletilebilir"""
        # Mevcut widget'ları temizle
        for widget in self.result_text.master.winfo_children():
            if isinstance(widget, tk.Frame) and widget != self.result_text.master.winfo_children()[0]:
                widget.destroy()
        
        # Seçim frame'i - daha büyük ve genişletilebilir
        selection_frame = tk.Frame(
            self.result_text.master, 
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0,
            padx=15,
            pady=15
        )
        selection_frame.pack(side='bottom', fill='both', expand=True, padx=20, pady=(10, 10))
        
        # Header frame
        header_frame = tk.Frame(selection_frame, bg=self.colors['bg_card'])
        header_frame.pack(fill='x', pady=(0, 15))
        
        # Başlık
        title = tk.Label(
            header_frame,
            text="📋 CVE Seçimi - LLM Çözüm Önerisi için CVE'leri Seçin:",
            font=("Segoe UI", 13, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='left')
        
        # Buton frame
        button_frame = tk.Frame(header_frame, bg=self.colors['bg_card'])
        button_frame.pack(side='right')
        
        # Tümünü seç butonu
        select_all_btn = tk.Button(
            button_frame,
            text="✓ Tümünü Seç",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            padx=12,
            pady=5,
            command=self.select_all_cves
        )
        select_all_btn.pack(side='left', padx=5)
        
        # Seçimi kaldır butonu
        deselect_all_btn = tk.Button(
            button_frame,
            text="✗ Seçimi Kaldır",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors['danger'],
            fg='white',
            relief='flat',
            padx=12,
            pady=5,
            command=self.deselect_all_cves
        )
        deselect_all_btn.pack(side='left', padx=5)
        
        # İstatistik etiketi
        self.cve_stats_label = tk.Label(
            button_frame,
            text=f"Toplam: {len(all_cves)} CVE",
            font=("Segoe UI", 10),
            fg=self.colors['text_gray'],
            bg=self.colors['bg_card']
        )
        self.cve_stats_label.pack(side='left', padx=15)
        
        # İçerik frame - genişletilebilir
        content_frame = tk.Frame(selection_frame, bg=self.colors['bg_card'])
        content_frame.pack(fill='both', expand=True)
        
        # Tree container
        tree_container = tk.Frame(content_frame, bg=self.colors['bg_card'])
        tree_container.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_container)
        scrollbar.pack(side='right', fill='y')
        
        # Treeview - daha büyük
        self.cve_tree = ttk.Treeview(
            tree_container,
            columns=('cve_id', 'service', 'port', 'description', 'severity'),
            show='headings',
            yscrollcommand=scrollbar.set,
            selectmode='extended',
            style='Custom.Treeview',
            height=8  # Daha yüksek
        )
        scrollbar.config(command=self.cve_tree.yview)
        
        # Sütun başlıkları
        self.cve_tree.heading('cve_id', text='CVE ID', anchor='w')
        self.cve_tree.heading('service', text='Servis', anchor='w')
        self.cve_tree.heading('port', text='Port', anchor='w')
        self.cve_tree.heading('description', text='Açıklama', anchor='w')
        self.cve_tree.heading('severity', text='Önem', anchor='center')
        
        # Sütun genişlikleri - daha geniş
        self.cve_tree.column('cve_id', width=130, anchor='w')
        self.cve_tree.column('service', width=180, anchor='w')
        self.cve_tree.column('port', width=70, anchor='center')
        self.cve_tree.column('description', width=450, anchor='w')
        self.cve_tree.column('severity', width=80, anchor='center')
        
        self.cve_tree.pack(fill='both', expand=True)
        
        # Treeview stili
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Custom.Treeview', 
                      background=self.colors['bg_input'],
                      foreground=self.colors['text_light'],
                      fieldbackground=self.colors['bg_input'],
                      borderwidth=0,
                      rowheight=25)  # Daha yüksek satırlar
        style.configure('Custom.Treeview.Heading', 
                      background=self.colors['secondary'],
                      foreground=self.colors['text_light'],
                      relief='flat',
                      font=('Segoe UI', 11, 'bold'))
        style.map('Custom.Treeview', 
                 background=[('selected', self.colors['primary'])],
                 foreground=[('selected', 'white')])
        
        # CVE'leri listeye ekle
        self.cve_vars = {} 
        for i, cve_data in enumerate(all_cves):
            cve = cve_data['cve']
            service = cve_data['service']
            port = cve_data['port']
            
            # Kısa açıklama
            short_desc = (cve['aciklama'][:97] + '...') if len(cve['aciklama']) > 100 else cve['aciklama']
            
            # Önem seviyesi (basit hesaplama)
            severity = "Yüksek" if any(keyword in cve['aciklama'].lower() for keyword in ['critical', 'high', 'severe', 'remote', 'execute']) else "Orta"
            
            # Treeview'a ekle
            item_id = self.cve_tree.insert('', 'end', 
                                         values=(cve['cve_id'], service, port, short_desc, severity),
                                         tags=('clickable',))
            
            # CVE verilerini sakla
            self.cve_vars[item_id] = {
                'cve': cve,
                'selected': False
            }
        
        # Çift tıklama olayı
        self.cve_tree.tag_bind('clickable', '<Double-1>', self.on_cve_double_click)
        
        # Alt frame
        bottom_frame = tk.Frame(content_frame, bg=self.colors['bg_card'])
        bottom_frame.pack(fill='x', pady=(15, 0))
        
        # Analiz butonu
        analyze_btn = self.create_rounded_button(
            bottom_frame, 
            "🤖 Seçilenler için LLM Analizi Başlat", 
            self.analyze_selected_cves, 
            'primary'
        )
        analyze_btn.pack(fill='x')
        
        # Seçim sayısını güncelle
        self.update_cve_selection_count()
        
        # Seçim değişikliği olayını bağla
        self.cve_tree.bind('<<TreeviewSelect>>', self.on_cve_selection_change)
    
    def update_cve_selection_count(self):
        """CVE seçim sayısını güncelle"""
        if hasattr(self, 'cve_stats_label'):
            selected_count = len(self.cve_tree.selection())
            total_count = len(self.cve_tree.get_children())
            self.cve_stats_label.config(text=f"Seçili: {selected_count}/{total_count} CVE")
    
    def on_cve_selection_change(self, event):
        """CVE seçimi değiştiğinde çağrılır"""
        self.update_cve_selection_count()
    
    def on_cve_double_click(self, event):
        """Treeview'da bir CVE'ye çift tıklandığında"""
        item = self.cve_tree.selection()[0]
        cve_data = self.cve_vars[item]['cve']
        
      
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"CVE Detay: {cve_data['cve_id']}")
        detail_window.geometry("600x400")
        detail_window.configure(bg=self.colors['bg_dark'])
        detail_window.resizable(True, True)
        
    
        title_frame = tk.Frame(detail_window, bg=self.colors['bg_dark'])
        title_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text=f" {cve_data['cve_id']} Detayları",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['primary'],
            bg=self.colors['bg_dark']
        )
        title_label.pack(side='left')
        
      
        content_frame = tk.Frame(detail_window, bg=self.colors['bg_card'])
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
   
        detail_text = scrolledtext.ScrolledText(
            content_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            padx=10,
            pady=10
        )
        detail_text.pack(fill='both', expand=True)
        
      
        detail_text.insert(tk.END, f" CVE ID: {cve_data['cve_id']}\n\n")
        detail_text.insert(tk.END, f" Açıklama:\n{cve_data['aciklama']}\n\n")
        
        
        self.center_window(detail_window)
    
    def center_window(self, window):
        """Pencereyi ekranın ortasına yerleştir"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
    
    def select_all_cves(self):
        """Tüm CVE'leri seç"""
        for item in self.cve_tree.get_children():
            self.cve_tree.selection_add(item)
            self.cve_vars[item]['selected'] = True
        self.update_cve_selection_count()
    
    def deselect_all_cves(self):
        """Tüm CVE seçimlerini kaldır"""
        self.cve_tree.selection_remove(self.cve_tree.get_children())
        for item in self.cve_vars:
            self.cve_vars[item]['selected'] = False
        self.update_cve_selection_count()
    
    def analyze_selected_cves(self):
        """Seçilen CVE'ler için LLM analizi yap"""
        selected_items = self.cve_tree.selection()
        
        if not selected_items:
            messagebox.showwarning("Uyarı", "Lütfen en az bir CVE seçin!")
            return
        
        selected_cves = []
        for item in selected_items:
            selected_cves.append(self.cve_vars[item]['cve'])
            self.cve_vars[item]['selected'] = True
        
        
        self.get_selected_llm_solutions(selected_cves)
    
    def get_selected_llm_solutions(self, selected_cves):
        """Seçilen CVE'ler için LLM çözüm önerilerini al"""
        def run_llm_analysis():
            self.result_text.insert(tk.END, f"\n {len(selected_cves)} seçilen CVE için LLM analizi başlatılıyor...\n")
            self.result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                for i, cve in enumerate(selected_cves, 1):
                    self.result_text.insert(tk.END, f" {i}/{len(selected_cves)} - {cve['cve_id']} analiz ediliyor...\n")
                    self.root.update()
                    
                    try:
                        # LLM çözüm önerisi al
                        llm_solution = llm_cozum_onerisi_getir(cve['aciklama'])
                        
                        self.result_text.insert(tk.END, f"\n CVE ID: {cve['cve_id']}\n")
                        self.result_text.insert(tk.END, f" Açıklama: {cve['aciklama']}\n")
                        self.result_text.insert(tk.END, "=" * 50 + "\n")
                        self.result_text.insert(tk.END, f" LLM Çözüm Önerisi:\n{llm_solution}\n")
                        self.result_text.insert(tk.END, "=" * 50 + "\n\n")
                        
                        # Sonucu sakla
                        self.current_analysis_result += f"\n CVE ID: {cve['cve_id']}\n"
                        self.current_analysis_result += f" Açıklama: {cve['aciklama']}\n"
                        self.current_analysis_result += f" LLM Çözüm Önerisi:\n{llm_solution}\n"
                        self.current_analysis_result += "=" * 50 + "\n\n"
                        
                    except Exception as e:
                        self.result_text.insert(tk.END, f" {cve['cve_id']} için LLM analizi hatası: {str(e)}\n\n")
                        continue
                    
                    # Her 2 CVE'de bir kısa bekleme (rate limiting için)
                    if i % 2 == 0:
                        self.result_text.insert(tk.END, " Kısa bir bekleme...\n")
                        self.root.update()
                        import time
                        time.sleep(0.5)  # 0.5 saniye bekleme
                
                self.result_text.insert(tk.END, f" Seçilen CVE'ler için LLM analizi tamamlandı!\n")
                self.result_text.insert(tk.END, f" Sonuçları kaydetmek için 'Sonucu Kaydet' butonuna tıklayın.\n")
                
            except Exception as e:
                self.result_text.insert(tk.END, f"\n LLM analizi genel hatası: {str(e)}\n")
        
        threading.Thread(target=run_llm_analysis, daemon=True).start()
    
    def save_llm_results_to_file(self, llm_text_content, selected_cves):
        """LLM sonuçlarını dosyaya kaydet"""
        # Dosya formatı seçimi
        file_types = [
            ("PDF Dosyası", "*.pdf"),
            ("Metin Dosyası", "*.txt"),
            ("Tüm Dosyalar", "*.*")
        ]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"llm_analiz_sonuclari_{timestamp}"
        
        file_path = filedialog.asksaveasfilename(
            title="LLM Analiz Sonuçlarını Kaydet",
            defaultextension=".pdf",
            filetypes=file_types,
            initialfile=default_filename
        )
        
        if file_path:
            try:
                file_extension = os.path.splitext(file_path)[1].lower()
                
                if file_extension == '.pdf' and PDF_AVAILABLE:
                    self.create_llm_pdf_report(file_path, llm_text_content, selected_cves)
                    messagebox.showinfo("✅ Başarılı", f"LLM analiz sonuçları PDF olarak kaydedildi:\n{file_path}")
                else:
                    # TXT dosyası olarak kaydet
                    if file_extension != '.txt':
                        file_path = file_path + '.txt'
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("🤖 Zafiyet Bulucu Pro - LLM Analiz Raporu\n")
                        f.write("=" * 60 + "\n")
                        f.write(f"📅 Tarih: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                        f.write(f"🔍 IP Adresi: {self.ip_entry.get().strip()}\n")
                        f.write(f"📋 Analiz Edilen CVE Sayısı: {len(selected_cves)}\n")
                        f.write("=" * 60 + "\n\n")
                        f.write(llm_text_content)
                        f.write("\n\n✅ LLM Analizi tamamlandı!")
                    
                    messagebox.showinfo("✅ Başarılı", f"LLM analiz sonuçları kaydedildi:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("❌ Hata", f"Dosya kaydedilirken hata oluştu:\n{str(e)}")
    
    def create_llm_pdf_report(self, file_path, llm_text_content, selected_cves):
        """LLM analiz sonuçları için PDF raporu oluştur"""
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        story = []
        
        # Türkçe karakter desteği için font ayarları
        try:
            # Helvetica kullan (en güvenilir)
            default_font = 'Helvetica'
        except:
            # Fallback
            default_font = 'Helvetica'
        
        # Stil tanımlamaları
        styles = getSampleStyleSheet()
        
        # Başlık stili
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue,
            fontName=default_font
        )
        
        # Alt başlık stili
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.darkred,
            fontName=default_font
        )
        
        # Normal metin stili
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            alignment=TA_JUSTIFY,
            fontName=default_font
        )
        
        # Başlık
        story.append(Paragraph(sanitize_for_pdf("Zafiyet Bulucu Pro - LLM Analiz Raporu"), title_style))
        story.append(Spacer(1, 20))
        
        # Rapor bilgileri tablosu
        report_data = [
            ['Rapor Bilgileri', ''],
            ['Tarih', sanitize_for_pdf(datetime.now().strftime('%d/%m/%Y %H:%M:%S'))],
            ['IP Adresi', sanitize_for_pdf(self.ip_entry.get().strip())],
            ['Analiz Edilen CVE Sayisi', sanitize_for_pdf(str(len(selected_cves)))],
            ['Rapor Turu', sanitize_for_pdf('LLM Cozum Onerisi Analizi')]
        ]
        
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), default_font),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), default_font)
        ]))
        
        story.append(report_table)
        story.append(Spacer(1, 30))
        
        # LLM analiz sonuçları
        story.append(Paragraph(sanitize_for_pdf("LLM Cozum Onerileri"), subtitle_style))
        story.append(Spacer(1, 15))
        
        # LLM metnini paragraflara böl
        lines = llm_text_content.split('\n')
        current_paragraph = ""
        
        for line in lines:
            line = sanitize_for_pdf(line.strip())
            if line:
                if line.lower().startswith('cve id:') or line.lower().startswith('aciklama:') or 'LLM' in line:
                    if current_paragraph:
                        story.append(Paragraph(current_paragraph, normal_style))
                        current_paragraph = ""
                    story.append(Paragraph(line, normal_style))
                elif line.startswith('='):
                    if current_paragraph:
                        story.append(Paragraph(current_paragraph, normal_style))
                        current_paragraph = ""
                    story.append(Spacer(1, 10))
                else:
                    current_paragraph += line + " "
        
        if current_paragraph:
            story.append(Paragraph(current_paragraph, normal_style))
        
        story.append(Spacer(1, 30))
        story.append(Paragraph(sanitize_for_pdf("LLM Analizi tamamlandi!"), normal_style))
        
        # PDF oluştur
        doc.build(story)
    
    def save_analysis_result(self):
        """Analiz sonucunu dosyaya kaydet"""
        if not self.current_analysis_result:
            messagebox.showwarning("⚠️ Uyarı", "Kaydedilecek analiz sonucu bulunamadı.\n\nÖnce '🔍 Servisleri Bul & CVE Analizi' butonuna tıklayarak analiz yapın veya LLM analizi sonuçlarını kaydedin.")
            return
            
        # Dosya formatı seçimi
        file_types = [
            ("PDF Dosyası", "*.pdf"),
            ("Metin Dosyası", "*.txt"),
            ("Tüm Dosyalar", "*.*")
        ]
        
        # Dosya kaydetme dialogu
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"zafiyet_analizi_{timestamp}"
        
        file_path = filedialog.asksaveasfilename(
            title="Analiz Sonucunu Kaydet",
            defaultextension=".pdf",
            filetypes=file_types,
            initialfile=default_filename
        )
        
        if file_path:
            try:
                file_extension = os.path.splitext(file_path)[1].lower()
                
                if file_extension == '.pdf' and PDF_AVAILABLE:
                    self.create_analysis_pdf_report(file_path)
                    messagebox.showinfo("✅ Başarılı", f"Analiz sonucu PDF olarak kaydedildi:\n{file_path}")
                else:
                    # TXT dosyası olarak kaydet
                    if file_extension != '.txt':
                        file_path = file_path + '.txt'
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("🔍 Zafiyet Bulucu Pro - Analiz Raporu\n")
                        f.write("=" * 60 + "\n")
                        f.write(f"📅 Tarih: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                        f.write(f"🔍 IP Adresi: {self.ip_entry.get().strip()}\n")
                        f.write("=" * 60 + "\n\n")
                        f.write(self.current_analysis_result)
                        f.write("\n\n✅ Analiz tamamlandı!")
                    
                    messagebox.showinfo("✅ Başarılı", f"Analiz sonucu kaydedildi:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("❌ Hata", f"Dosya kaydedilirken hata oluştu:\n{str(e)}")
    
    def create_analysis_pdf_report(self, file_path):
        """Ana analiz sonuçları için PDF raporu oluştur"""
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        story = []
        
        # Türkçe karakter desteği için font ayarları
        try:
            # Helvetica kullan (en güvenilir)
            default_font = 'Helvetica'
        except:
            # Fallback
            default_font = 'Helvetica'
        
        # Stil tanımlamaları
        styles = getSampleStyleSheet()
        
        # Başlık stili
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue,
            fontName=default_font
        )
        
        # Alt başlık stili
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.darkred,
            fontName=default_font
        )
        
        # Normal metin stili
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            alignment=TA_JUSTIFY,
            fontName=default_font
        )
        
        # Başlık
        story.append(Paragraph(sanitize_for_pdf("Zafiyet Bulucu Pro - Analiz Raporu"), title_style))
        story.append(Spacer(1, 20))
        
        # Rapor bilgileri tablosu
        total_services = len(self.found_services) if hasattr(self, 'found_services') else 0
        analyzed_services = len(self.cve_results) if hasattr(self, 'found_services') else 0
        skipped_services = total_services - analyzed_services
        total_cves = sum(len(cves) for cves in self.cve_results.values()) if hasattr(self, 'cve_results') else 0
        
        report_data = [
            ['Rapor Bilgileri', ''],
            ['Tarih', sanitize_for_pdf(datetime.now().strftime('%d/%m/%Y %H:%M:%S'))],
            ['IP Adresi', sanitize_for_pdf(self.ip_entry.get().strip())],
            ['Toplam Servis Sayisi', sanitize_for_pdf(str(total_services))],
            ['Analiz Edilen Servis', sanitize_for_pdf(str(analyzed_services))],
            ['Atlanan Servis (Surum Yok)', sanitize_for_pdf(str(skipped_services))],
            ['Bulunan CVE Sayisi', sanitize_for_pdf(str(total_cves))],
            ['Rapor Turu', sanitize_for_pdf('Genel Zafiyet Analizi')]
        ]
        
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), default_font),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), default_font)
        ]))
        
        story.append(report_table)
        story.append(Spacer(1, 30))
        
        # Analiz sonuçları
        story.append(Paragraph(sanitize_for_pdf("Analiz Sonuclari"), subtitle_style))
        story.append(Spacer(1, 15))
        
        # Servis detayları tablosu
        if hasattr(self, 'found_services') and self.found_services:
            story.append(Paragraph(sanitize_for_pdf("Tespit Edilen Servisler"), subtitle_style))
            story.append(Spacer(1, 10))
            
            service_data = [[sanitize_for_pdf('Port'), sanitize_for_pdf('Urun'), sanitize_for_pdf('Surum'), sanitize_for_pdf('Durum')]]
            for service in self.found_services:
                port = sanitize_for_pdf(str(service.get('port', 'N/A')))
                urun = sanitize_for_pdf(service.get('urun', 'N/A'))
                surum = sanitize_for_pdf(service.get('surum', 'Surum bilgisi yok'))
                
                # Sürüm bilgisi varsa analiz edildi olarak işaretle
                if surum and surum != 'Surum bilgisi yok':
                    status = sanitize_for_pdf("Analiz edildi")
                else:
                    status = sanitize_for_pdf("Surum yok - atlandi")
                
                service_data.append([port, urun, surum, status])
            
            service_table = Table(service_data, colWidths=[0.8*inch, 2*inch, 1.5*inch, 1.5*inch])
            service_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), default_font),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('FONTNAME', (0, 1), (-1, -1), default_font)
            ]))
            
            story.append(service_table)
            story.append(Spacer(1, 20))
        
        # CVE detayları
        if hasattr(self, 'cve_results') and self.cve_results:
            story.append(Paragraph(sanitize_for_pdf("Bulunan CVE'ler"), subtitle_style))
            story.append(Spacer(1, 10))
            
            for service_name, cves in self.cve_results.items():
                if cves:
                    story.append(Paragraph(sanitize_for_pdf(f"Servis: {service_name}"), normal_style))
                    story.append(Spacer(1, 5))
                    
                    for cve in cves[:3]:  # En fazla 3 CVE göster
                        cve_text = sanitize_for_pdf(f"CVE: {cve.get('cve_id', 'N/A')}")
                        if cve.get('version_match'):
                            cve_text += sanitize_for_pdf(" - Surum eslesmesi")
                        else:
                            cve_text += sanitize_for_pdf(" - Surum belirsiz")
                        
                        story.append(Paragraph(cve_text, normal_style))
                        story.append(Paragraph(sanitize_for_pdf(f"Aciklama: {cve.get('aciklama', '')[:100]}..."), normal_style))
                        story.append(Spacer(1, 5))
                    
                    if len(cves) > 3:
                        story.append(Paragraph(sanitize_for_pdf(f"... ve {len(cves) - 3} CVE daha"), normal_style))
                    
                    story.append(Spacer(1, 10))
        
        # Analiz metnini paragraflara böl
        lines = self.current_analysis_result.split('\n')
        current_paragraph = ""
        
        for line in lines:
            line = line.strip()
            if line:
                if line.startswith('🔍') or line.startswith('📡') or line.startswith('🎯') or line.startswith('📋'):
                    if current_paragraph:
                        story.append(Paragraph(current_paragraph, normal_style))
                        current_paragraph = ""
                    story.append(Paragraph(line, normal_style))
                elif line.startswith('='):
                    if current_paragraph:
                        story.append(Paragraph(current_paragraph, normal_style))
                        current_paragraph = ""
                    story.append(Spacer(1, 10))
                else:
                    current_paragraph += line + " "
        
        if current_paragraph:
            story.append(Paragraph(sanitize_for_pdf(current_paragraph), normal_style))
        
        story.append(Spacer(1, 30))
        story.append(Paragraph(sanitize_for_pdf("Analiz tamamlandi!"), normal_style))
        
        # PDF oluştur
        doc.build(story)
    
    def show_nmap_scan_card(self):
        """Hızlı Nmap tarama kartını göster"""
        for widget in self.card_frame.winfo_children():
            widget.destroy()
            
        # Ana kart
        card = tk.Frame(
            self.card_frame,
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0
        )
        card.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Üst bar
        top_bar = tk.Frame(card, bg=self.colors['bg_card'])
        top_bar.pack(fill='x', padx=20, pady=20)
        
        # Geri butonu
        back_btn = self.create_rounded_button(
            top_bar, "← Geri", self.show_main_menu_card, 'warning', 'small'
        )
        back_btn.pack(side='left')
        
        # Başlık
        title = tk.Label(
            top_bar,
            text="⚡ Hızlı Nmap Tarama",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='right')
        
        # Sol panel
        left_panel = tk.Frame(card, bg=self.colors['bg_card'])
        left_panel.pack(side='left', fill='y', padx=(40, 20), pady=30)
        
        # IP girişi
        input_label = tk.Label(
            left_panel,
            text="IP Adresi:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        input_label.pack(anchor='w', pady=(0, 10))
        
        # Input container
        input_container = tk.Frame(left_panel, bg=self.colors['bg_input'], relief='flat', bd=0)
        input_container.pack(fill='x', pady=(0, 20))
        
        self.nmap_ip_entry = tk.Entry(
            input_container,
            font=("Consolas", 14),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light']
        )
        self.nmap_ip_entry.pack(fill='x', padx=15, pady=15)
        
        # Port aralığı seçimi
        port_label = tk.Label(
            left_panel,
            text="Port Aralığı:",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        port_label.pack(anchor='w', pady=(20, 10))
        
        # Port aralığı combobox
        port_frame = tk.Frame(left_panel, bg=self.colors['bg_input'], relief='flat', bd=0)
        port_frame.pack(fill='x', pady=(0, 20))
        
        self.port_range_var = tk.StringVar(value="1-1000")
        port_combo = ttk.Combobox(
            port_frame,
            textvariable=self.port_range_var,
            values=["1-100", "1-1000", "1-10000", "1-65535"],
            font=("Consolas", 12),
            state="readonly"
        )
        port_combo.pack(fill='x', padx=15, pady=15)
        
        # Buton container
        button_container = tk.Frame(left_panel, bg=self.colors['bg_card'])
        button_container.pack(fill='x', pady=20)
        
        # Hızlı port tarama butonu
        quick_btn = self.create_rounded_button(
            button_container, "⚡ Hızlı Port Tarama", self.quick_port_scan, 'success'
        )
        quick_btn.pack(fill='x', pady=(0, 10))
        
        # Servis tarama butonu
        service_btn = self.create_rounded_button(
            button_container, "🔍 Servis & Sürüm Tarama", self.service_scan, 'primary'
        )
        service_btn.pack(fill='x', pady=(0, 10))
        
        # Tam analiz butonu
        full_btn = self.create_rounded_button(
            button_container, "🎯 Tam Analiz (Port + Servis + CVE)", self.full_nmap_analysis, 'accent'
        )
        full_btn.pack(fill='x')
        
        # Sağ panel
        right_panel = tk.Frame(card, bg=self.colors['bg_card'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(20, 40), pady=30)
        
        result_label = tk.Label(
            right_panel,
            text=" Tarama Sonuçları:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        result_label.pack(anchor='w', pady=(0, 10))
        
        # Sonuç text alanı
        self.nmap_result_text = scrolledtext.ScrolledText(
            right_panel,
            height=25,
            font=("Consolas", 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light'],
            selectbackground=self.colors['primary']
        )
        self.nmap_result_text.pack(fill='both', expand=True)
    
    def quick_port_scan(self):
        """Hızlı port tarama"""
        ip = self.nmap_ip_entry.get().strip()
        port_range = self.port_range_var.get()
        
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_quick_scan():
            self.nmap_result_text.delete(1.0, tk.END)
            self.nmap_result_text.insert(tk.END, f"⚡ {ip} için hızlı port taraması başlatılıyor...\n")
            self.nmap_result_text.insert(tk.END, f"📡 Port aralığı: {port_range}\n")
            self.nmap_result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                acik_portlar = nmap_hizli_port_tarama(ip, port_range)
                
                if acik_portlar:
                    self.nmap_result_text.insert(tk.END, f"✅ Tarama tamamlandı! {len(acik_portlar)} açık port bulundu:\n\n")
                    for port in sorted(acik_portlar):
                        self.nmap_result_text.insert(tk.END, f"🔓 Port {port} açık\n")
                else:
                    self.nmap_result_text.insert(tk.END, "❌ Açık port bulunamadı.\n")
                    
            except Exception as e:
                self.nmap_result_text.insert(tk.END, f"\n❌ Hata: {str(e)}\n")
                
        threading.Thread(target=run_quick_scan, daemon=True).start()
    
    def service_scan(self):
        """Servis ve sürüm tarama"""
        ip = self.nmap_ip_entry.get().strip()
        port_range = self.port_range_var.get()
        
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_service_scan():
            self.nmap_result_text.delete(1.0, tk.END)
            self.nmap_result_text.insert(tk.END, f"🔍 {ip} için servis taraması başlatılıyor...\n")
            self.nmap_result_text.insert(tk.END, f"📡 Port aralığı: {port_range}\n")
            self.nmap_result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                servisler = nmap_ile_servisleri_bul(ip, port_range)
                
                if servisler:
                    self.nmap_result_text.insert(tk.END, f"✅ Tarama tamamlandı! {len(servisler)} servis bulundu:\n\n")
                    
                    for servis in servisler:
                        port = servis['port']
                        urun = servis['urun']
                        surum = servis['surum']
                        
                        self.nmap_result_text.insert(tk.END, f"🔍 Port {port}:\n")
                        self.nmap_result_text.insert(tk.END, f"   📋 Ürün: {urun}\n")
                        self.nmap_result_text.insert(tk.END, f"   📦 Sürüm: {surum or 'Bilinmiyor'}\n")
                        self.nmap_result_text.insert(tk.END, "-" * 40 + "\n")
                else:
                    self.nmap_result_text.insert(tk.END, "❌ Servis bulunamadı.\n")
                    
            except Exception as e:
                self.nmap_result_text.insert(tk.END, f"\n❌ Hata: {str(e)}\n")
                
        threading.Thread(target=run_service_scan, daemon=True).start()
    
    def full_nmap_analysis(self):
        """Tam analiz (Port + Servis + CVE)"""
        ip = self.nmap_ip_entry.get().strip()
        port_range = self.port_range_var.get()
        
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_full_analysis():
            self.nmap_result_text.delete(1.0, tk.END)
            self.nmap_result_text.insert(tk.END, f"🎯 {ip} için tam analiz başlatılıyor...\n")
            self.nmap_result_text.insert(tk.END, f"📡 Port aralığı: {port_range}\n")
            self.nmap_result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                # 1. Servis tarama
                self.nmap_result_text.insert(tk.END, "🔍 1. Adım: Servis taraması...\n")
                servisler = nmap_ile_servisleri_bul(ip, port_range)
                
                if not servisler:
                    self.nmap_result_text.insert(tk.END, "❌ Servis bulunamadı. Analiz sonlandırılıyor.\n")
                    return
                
                self.nmap_result_text.insert(tk.END, f"✅ {len(servisler)} servis bulundu!\n\n")
                
                # 2. CVE analizi
                self.nmap_result_text.insert(tk.END, "🔍 2. Adım: CVE analizi...\n")
                total_cves = 0
                cve_results = {}
                
                for i, servis in enumerate(servisler, 1):
                    urun = servis['urun']
                    surum = servis['surum']
                    port = servis['port']
                    
                    self.nmap_result_text.insert(tk.END, f"📋 [{i}/{len(servisler)}] {urun} (Port: {port})\n")
                    
                    if not surum:
                        self.nmap_result_text.insert(tk.END, f"   ⚠️ Sürüm bilgisi yok - CVE analizi atlanıyor.\n\n")
                        continue
                    
                    self.nmap_result_text.insert(tk.END, f"   📦 Sürüm: {surum}\n")
                    self.nmap_result_text.insert(tk.END, f"   🔍 CVE aranıyor...\n")
                    
                    cve_listesi = mitre_cve_ara(urun, surum)
                    
                    if cve_listesi:
                        self.nmap_result_text.insert(tk.END, f"   ✅ {len(cve_listesi)} CVE bulundu!\n")
                        total_cves += len(cve_listesi)
                        cve_results[f"{urun}_{surum}"] = cve_listesi
                        
                        for j, cve in enumerate(cve_listesi[:3], 1):
                            self.nmap_result_text.insert(tk.END, f"      {j}. {cve['cve_id']}: {cve['aciklama'][:80]}...\n")
                        
                        if len(cve_listesi) > 3:
                            self.nmap_result_text.insert(tk.END, f"      ... ve {len(cve_listesi) - 3} CVE daha\n")
                    else:
                        self.nmap_result_text.insert(tk.END, f"   ❌ CVE bulunamadı.\n")
                    
                    self.nmap_result_text.insert(tk.END, "\n")
                    
                    if i < len(servisler):
                        self.root.update()
                        import time
                        time.sleep(0.2)
                
                # 3. Özet
                self.nmap_result_text.insert(tk.END, f"🎯 Tam analiz tamamlandı!\n")
                self.nmap_result_text.insert(tk.END, f"📊 Özet:\n")
                self.nmap_result_text.insert(tk.END, f"   • Toplam Servis: {len(servisler)}\n")
                self.nmap_result_text.insert(tk.END, f"   • Analiz Edilen: {len(cve_results)}\n")
                self.nmap_result_text.insert(tk.END, f"   • Bulunan CVE: {total_cves}\n")
                
                # Sonuçları sakla
                self.found_services = servisler
                self.cve_results = cve_results
                self.current_analysis_result = f"🔍 IP Adresi: {ip}\n"
                self.current_analysis_result += f"📡 Toplam Servis: {len(servisler)}\n"
                self.current_analysis_result += f"🎯 Bulunan CVE: {total_cves}\n"
                self.current_analysis_result += "=" * 60 + "\n\n"
                
                for service_key, cve_list in cve_results.items():
                    self.current_analysis_result += f"📋 Servis: {service_key.replace('_', ' ')}\n"
                    for cve in cve_list:
                        self.current_analysis_result += f"  🔍 {cve['cve_id']}: {cve['aciklama']}\n"
                    self.current_analysis_result += "\n"
                    
            except Exception as e:
                self.nmap_result_text.insert(tk.END, f"\n❌ Hata: {str(e)}\n")
                
        threading.Thread(target=run_full_analysis, daemon=True).start()
        
    def show_port_list_card(self):
       
        for widget in self.card_frame.winfo_children():
            widget.destroy()
            
     
        card = tk.Frame(
            self.card_frame,
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0
        )
        card.pack(fill='both', expand=True, padx=20, pady=20)
        

        top_bar = tk.Frame(card, bg=self.colors['bg_card'])
        top_bar.pack(fill='x', padx=20, pady=20)
        

        back_btn = self.create_rounded_button(
            top_bar, "← Geri", self.show_main_menu_card, 'warning', 'small'
        )
        back_btn.pack(side='left')
        
        title = tk.Label(
            top_bar,
            text=" Açık Port Taraması",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='right')
        
  
        left_panel = tk.Frame(card, bg=self.colors['bg_card'])
        left_panel.pack(side='left', fill='y', padx=(40, 20), pady=30)
        
       
        ip_label = tk.Label(
            left_panel,
            text="IP Adresi:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        ip_label.pack(anchor='w', pady=(0, 10))
        
        
        input_container = tk.Frame(left_panel, bg=self.colors['bg_input'], relief='flat', bd=0)
        input_container.pack(fill='x', pady=(0, 20))
        
        self.port_ip_entry = tk.Entry(
            input_container,
            font=("Consolas", 14),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light']
        )
        self.port_ip_entry.pack(fill='x', padx=15, pady=15)
        
        
        list_btn = self.create_rounded_button(
            left_panel, " Portları Tara", self.list_ports, 'accent'
        )
        list_btn.pack(pady=20)
        
        
        right_panel = tk.Frame(card, bg=self.colors['bg_card'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(20, 40), pady=30)
        
        result_label = tk.Label(
            right_panel,
            text=" Port Tarama Sonuçları:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        result_label.pack(anchor='w', pady=(0, 10))
        
        
        self.port_result_text = scrolledtext.ScrolledText(
            right_panel,
            height=25,
            font=("Consolas", 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light'],
            selectbackground=self.colors['primary']
        )
        self.port_result_text.pack(fill='both', expand=True)
        
    def list_ports(self):
        ip = self.port_ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_port_scan():
            self.port_result_text.delete(1.0, tk.END)
            self.port_result_text.insert(tk.END, f" {ip} portları taranıyor...\n")
            self.port_result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                
                with self.output_capture.capture_output():
                    shodan_ip_acik_portlari_goster(ip)
                
                
                self.port_result_text.insert(tk.END, self.output_capture.output)
                self.port_result_text.insert(tk.END, "\n Port taraması tamamlandı!\n")
            except Exception as e:
                self.port_result_text.insert(tk.END, f"\n Hata: {str(e)}\n")
                
        threading.Thread(target=run_port_scan, daemon=True).start()
        
    def show_general_search_card(self):
        
        for widget in self.card_frame.winfo_children():
            widget.destroy()
            
        
        card = tk.Frame(
            self.card_frame,
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0
        )
        card.pack(fill='both', expand=True, padx=20, pady=20)
        
       
        top_bar = tk.Frame(card, bg=self.colors['bg_card'])
        top_bar.pack(fill='x', padx=20, pady=20)
        
        
        back_btn = self.create_rounded_button(
            top_bar, "← Geri", self.show_main_menu_card, 'warning', 'small'
        )
        back_btn.pack(side='left')
        
        
        title = tk.Label(
            top_bar,
            text=" Shodan Arama",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='right')
        
        
        left_panel = tk.Frame(card, bg=self.colors['bg_card'])
        left_panel.pack(side='left', fill='y', padx=(40, 20), pady=30)
        
        
        search_label = tk.Label(
            left_panel,
            text="Arama Terimi:",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        search_label.pack(anchor='w', pady=(0, 10))
        
        
        input_container = tk.Frame(left_panel, bg=self.colors['bg_input'], relief='flat', bd=0)
        input_container.pack(fill='x', pady=(0, 20))
        
        self.search_entry = tk.Entry(
            input_container,
            font=("Consolas", 14),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light']
        )
        self.search_entry.pack(fill='x', padx=15, pady=15)
        
       
        search_btn = self.create_rounded_button(
            left_panel, " Ara", self.general_search, 'danger'
        )
        search_btn.pack(pady=20)
        
        
        right_panel = tk.Frame(card, bg=self.colors['bg_card'])
        right_panel.pack(side='right', fill='both', expand=True, padx=(20, 40), pady=30)
        
        result_label = tk.Label(
            right_panel,
            text=" Arama Sonuçları:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        result_label.pack(anchor='w', pady=(0, 10))
        
        
        self.search_result_text = scrolledtext.ScrolledText(
            right_panel,
            height=25,
            font=("Consolas", 11),
            bg=self.colors['bg_input'],
            fg=self.colors['text_light'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_light'],
            selectbackground=self.colors['primary']
        )
        self.search_result_text.pack(fill='both', expand=True)
        
    def general_search(self):
        search_term = self.search_entry.get().strip()
        if not search_term:
            messagebox.showerror("Hata", "Lütfen bir arama terimi girin!")
            return
            
        def run_search():
            self.search_result_text.delete(1.0, tk.END)
            self.search_result_text.insert(tk.END, f" '{search_term}' aranıyor...\n")
            self.search_result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                
                with self.output_capture.capture_output():
                    shodan_genel_arama(search_term)
                
                
                self.search_result_text.insert(tk.END, self.output_capture.output)
                self.search_result_text.insert(tk.END, "\n Arama tamamlandı!\n")
            except Exception as e:
                self.search_result_text.insert(tk.END, f"\n Hata: {str(e)}\n")
                
        threading.Thread(target=run_search, daemon=True).start()

def main():
    load_dotenv()
    root = tk.Tk()
    app = ModernUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()