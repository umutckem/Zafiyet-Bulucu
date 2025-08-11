import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from Api_Shodan import shodan_servisleri_al, nmap_ile_surumu_bul, shodan_port_sorgula, shodan_genel_arama
from Main import mitre_cve_ara, llm_cozum_onerisi_getir, shodan_mitre_llm_analiz, shodan_ip_acik_portlari_goster
from output_capture import OutputCapture

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
        
        
        buttons = [
            (" IP Zafiyet Analizi", self.show_ip_analysis_card, 'primary'),
            (" Açık Port Taraması", self.show_port_list_card, 'secondary'),
            (" Shodan Arama", self.show_general_search_card, 'accent'),
            (" Çıkış", self.root.quit, 'danger')
        ]
        
    
        for i, (text, command, color) in enumerate(buttons):
            row = i // 2
            col = i % 2
            btn = self.create_rounded_button(button_frame, text, command, color)
            btn.grid(row=row, column=col, padx=20, pady=15, sticky='ew')
        
      
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
            
    def show_ip_analysis_card(self):
   
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
            text=" IP Zafiyet Analizi",
            font=("Segoe UI", 20, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='right')
        
       
        left_panel = tk.Frame(card, bg=self.colors['bg_card'])
        left_panel.pack(side='left', fill='y', padx=(40, 20), pady=30)
        
      
        input_label = tk.Label(
            left_panel,
            text="IP Adresi:",
            font=("Segoe UI", 14, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        input_label.pack(anchor='w', pady=(0, 10))
        
       
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
        
   
        button_container = tk.Frame(left_panel, bg=self.colors['bg_card'])
        button_container.pack(fill='x', pady=20)
        
       
        port_btn = self.create_rounded_button(
            button_container, " Portları Tara", self.scan_ports, 'accent'
        )
        port_btn.pack(fill='x', pady=(0, 10))
        
      
        analyze_btn = self.create_rounded_button(
            button_container, " Servisleri Bul", self.find_services, 'success'
        )
        analyze_btn.pack(fill='x', pady=(0, 10))
        
       
        cve_btn = self.create_rounded_button(
            button_container, " CVE Analizi", self.analyze_cves, 'danger'
        )
        cve_btn.pack(fill='x', pady=(0, 10))
        
       
        save_btn = self.create_rounded_button(
            button_container, " Sonucu Kaydet", self.save_analysis_result, 'primary'
        )
        save_btn.pack(fill='x')
        
       
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
        
    def scan_ports(self):
        """IP'deki açık portları tara"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_port_scan():
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f" {ip} portları taranıyor...\n")
            self.result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
               
                with self.output_capture.capture_output():
                    shodan_ip_acik_portlari_goster(ip)
                
             
                self.result_text.insert(tk.END, self.output_capture.output)
                self.result_text.insert(tk.END, "\n Port taraması tamamlandı!\n")
                self.result_text.insert(tk.END, " Şimdi 'Servisleri Bul' butonuna tıklayarak detaylı analiz yapabilirsiniz.\n")
                
            except Exception as e:
                self.result_text.insert(tk.END, f"\n Hata: {str(e)}\n")
                
        threading.Thread(target=run_port_scan, daemon=True).start()
        
    def find_services(self):
        """IP'deki servisleri bul"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "Lütfen bir IP adresi girin!")
            return
            
        def run_service_scan():
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f" {ip} servisleri taranıyor...\n")
            self.result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                # Shodan'dan servisleri al
                self.found_services = shodan_servisleri_al(ip)
                
                if not self.found_services:
                    self.result_text.insert(tk.END, " Bu IP'de Shodan'da servis kaydı bulunamadı.\n")
                    self.result_text.insert(tk.END, " Önce 'Portları Tara' butonunu kullanarak port taraması yapabilirsiniz.\n")
                    return
                
                # Servisleri göster
                self.result_text.insert(tk.END, f" {len(self.found_services)} servis bulundu:\n\n")
                
                for i, service in enumerate(self.found_services, 1):
                    self.result_text.insert(tk.END, f" Servis {i}:\n")
                    self.result_text.insert(tk.END, f"   Port: {service['port']}\n")
                    self.result_text.insert(tk.END, f"   Ürün: {service['urun']}\n")
                    self.result_text.insert(tk.END, f"   Sürüm: {service['surum'] or 'Bilinmiyor'}\n")
                    self.result_text.insert(tk.END, "-" * 40 + "\n")
                
                self.result_text.insert(tk.END, "\n CVE analizi için 'CVE Analizi' butonuna tıklayın.\n")
                
            except Exception as e:
                self.result_text.insert(tk.END, f"\n Hata: {str(e)}\n")
                
        threading.Thread(target=run_service_scan, daemon=True).start()
        
    def analyze_cves(self):
        """Bulunan servisler için CVE analizi yap"""
        if not self.found_services:
            messagebox.showwarning("Uyarı", "Önce servisleri bulun! 'Servisleri Bul' butonuna tıklayın.")
            return
            
        def run_cve_analysis():
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, " CVE analizi başlatılıyor...\n")
            self.result_text.insert(tk.END, "=" * 80 + "\n\n")
            self.root.update()
            
            try:
                total_cves = 0
                self.cve_results = {}
                all_cves = []  
                
          
                total_services = len(self.found_services)
                
                for i, service in enumerate(self.found_services, 1):
                    urun = service['urun']
                    surum = service['surum']
                    port = service['port']
                    
                    self.result_text.insert(tk.END, f"🔍 [{i}/{total_services}] {urun} {surum} analiz ediliyor...\n")
                    self.root.update()
                    
                
                    if not surum:
                        self.result_text.insert(tk.END, f"    Sürüm tespit ediliyor (nmap)...\n")
                        urun, surum = nmap_ile_surumu_bul(self.ip_entry.get().strip(), port)
                    
                    if not urun or not surum:
                        self.result_text.insert(tk.END, f"    Sürüm tespit edilemedi.\n\n")
                        continue
                    
          
                    self.result_text.insert(tk.END, f"    CVE kayıtları aranıyor...\n")
                    cve_listesi = mitre_cve_ara(urun, surum)
                    
                    if cve_listesi:
                        self.result_text.insert(tk.END, f"    {len(cve_listesi)} CVE bulundu!\n")
                        total_cves += len(cve_listesi)
                        self.cve_results[f"{urun}_{surum}"] = cve_listesi
                        
                   
                        for cve in cve_listesi:
                            all_cves.append({
                                'cve': cve,
                                'service': f"{urun} {surum}",
                                'port': port
                            })
                        
                     
                        for j, cve in enumerate(cve_listesi[:3], 1):
                            self.result_text.insert(tk.END, f"      {j}. {cve['cve_id']}: {cve['aciklama'][:100]}...\n")
                        
                        if len(cve_listesi) > 3:
                            self.result_text.insert(tk.END, f"      ... ve {len(cve_listesi) - 3} CVE daha\n")
                    else:
                        self.result_text.insert(tk.END, f"    CVE kaydı bulunamadı.\n")
                    
                    self.result_text.insert(tk.END, "\n")
                    
              
                    if i < total_services:
                        self.root.update()
                        import time
                        time.sleep(0.2)  
                
                self.result_text.insert(tk.END, f" Toplam {total_cves} CVE bulundu!\n")
                
                if all_cves:
                    self.result_text.insert(tk.END, " LLM çözüm önerileri için CVE seçimi yapın.\n")
                    self.result_text.insert(tk.END, "=" * 80 + "\n\n")
                    self.root.update()
                    
                
                    self.create_cve_selection_interface(all_cves)
                else:
                    self.result_text.insert(tk.END, " LLM analizi için CVE bulunamadı.\n")
                
            except Exception as e:
                self.result_text.insert(tk.END, f"\n Hata: {str(e)}\n")
                
        threading.Thread(target=run_cve_analysis, daemon=True).start()
        
    def create_cve_selection_interface(self, all_cves):
        """Modern CVE seçim arayüzü"""
  
        for widget in self.result_text.master.winfo_children():
            if isinstance(widget, tk.Frame) and widget != self.result_text.master.winfo_children()[0]:
                widget.destroy()
        
  
        selection_frame = tk.Frame(
            self.result_text.master, 
            bg=self.colors['bg_card'],
            relief='flat',
            bd=0,
            padx=10,
            pady=10
        )
        selection_frame.pack(side='bottom', fill='both', expand=False, padx=20, pady=(0, 10))
        
  
        header_frame = tk.Frame(selection_frame, bg=self.colors['bg_card'])
        header_frame.pack(fill='x', pady=(0, 10))
        
     
        title = tk.Label(
            header_frame,
            text=" LLM Çözüm Önerisi için CVE Seçin:",
            font=("Segoe UI", 12, "bold"),
            fg=self.colors['text_light'],
            bg=self.colors['bg_card']
        )
        title.pack(side='left')
        
      
        button_frame = tk.Frame(header_frame, bg=self.colors['bg_card'])
        button_frame.pack(side='right')
        
     
        select_all_btn = tk.Button(
            button_frame,
            text="✓ Tümünü Seç",
            font=("Segoe UI", 9, "bold"),
            bg=self.colors['success'],
            fg='white',
            relief='flat',
            padx=10,
            command=self.select_all_cves
        )
        select_all_btn.pack(side='left', padx=5)
        
        deselect_all_btn = tk.Button(
            button_frame,
            text="✗ Seçimi Kaldır",
            font=("Segoe UI", 9, "bold"),
            bg=self.colors['danger'],
            fg='white',
            relief='flat',
            padx=10,
            command=self.deselect_all_cves
        )
        deselect_all_btn.pack(side='left', padx=5)
        
      
        content_frame = tk.Frame(selection_frame, bg=self.colors['bg_card'])
        content_frame.pack(fill='both', expand=True)
        
 
        tree_container = tk.Frame(content_frame, bg=self.colors['bg_card'])
        tree_container.pack(fill='both', expand=True)
        
      
        scrollbar = ttk.Scrollbar(tree_container)
        scrollbar.pack(side='right', fill='y')
        
       
        self.cve_tree = ttk.Treeview(
            tree_container,
            columns=('cve_id', 'service', 'port', 'description'),
            show='headings',
            yscrollcommand=scrollbar.set,
            selectmode='extended',
            style='Custom.Treeview'
        )
        scrollbar.config(command=self.cve_tree.yview)
        
        self.cve_tree.heading('cve_id', text='CVE ID', anchor='w')
        self.cve_tree.heading('service', text='Servis', anchor='w')
        self.cve_tree.heading('port', text='Port', anchor='w')
        self.cve_tree.heading('description', text='Açıklama', anchor='w')
        
  
        self.cve_tree.column('cve_id', width=120, anchor='w')
        self.cve_tree.column('service', width=150, anchor='w')
        self.cve_tree.column('port', width=60, anchor='center')
        self.cve_tree.column('description', width=400, anchor='w')
        
        self.cve_tree.pack(fill='both', expand=True)
        
   
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
        
 
        self.cve_vars = {} 
        for i, cve_data in enumerate(all_cves):
            cve = cve_data['cve']
            service = cve_data['service']
            port = cve_data['port']
            
          
            short_desc = (cve['aciklama'][:97] + '...') if len(cve['aciklama']) > 100 else cve['aciklama']
            
         
            item_id = self.cve_tree.insert('', 'end', 
                                         values=(cve['cve_id'], service, port, short_desc),
                                         tags=('clickable',))
            
           
            self.cve_vars[item_id] = {
                'cve': cve,
                'selected': False
            }
        
       
        self.cve_tree.tag_bind('clickable', '<Double-1>', self.on_cve_double_click)
        
       
        bottom_frame = tk.Frame(content_frame, bg=self.colors['bg_card'])
        bottom_frame.pack(fill='x', pady=(10, 0))
        
       
        analyze_btn = self.create_rounded_button(
            bottom_frame, 
            " Seçilenler için LLM Analizi Başlat", 
            self.analyze_selected_cves, 
            'primary'
        )
        analyze_btn.pack(fill='x')
    
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
    
    def deselect_all_cves(self):
        """Tüm CVE seçimlerini kaldır"""
        self.cve_tree.selection_remove(self.cve_tree.get_children())
        for item in self.cve_vars:
            self.cve_vars[item]['selected'] = False
    
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
        
    def save_analysis_result(self):
        """Analiz sonucunu dosyaya kaydet"""
        if not self.current_analysis_result:
            messagebox.showwarning("Uyarı", "Kaydedilecek analiz sonucu bulunamadı. Önce bir analiz yapın.")
            return
            
        # Dosya kaydetme dialogu
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"zafiyet_analizi_{timestamp}.txt"
        
        file_path = filedialog.asksaveasfilename(
            title="Analiz Sonucunu Kaydet",
            defaultextension=".txt",
            filetypes=[
                ("Metin Dosyası", "*.txt"),
                ("Tüm Dosyalar", "*.*")
            ],
            initialvalue=default_filename
        )
        
        if file_path:
            try:
              
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(" Zafiyet Bulucu Pro - Analiz Raporu\n")
                    f.write("=" * 50 + "\n")
                    f.write(f" Tarih: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                    f.write(f" IP Adresi: {self.ip_entry.get().strip()}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(self.current_analysis_result)
                    f.write("\n\n Analiz tamamlandı!")
                
                messagebox.showinfo("Başarılı", f"Analiz sonucu başarıyla kaydedildi:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu:\n{str(e)}")
        
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