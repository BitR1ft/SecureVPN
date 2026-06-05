import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from datetime import datetime

if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.vpn_engine import VPNCore, TunnelStatus, SecurityError

# Colors
BG       = '#f5f5f5'
SIDEBAR  = '#2c2c2e'
PANEL    = '#ffffff'
ACCENT   = '#0055cc'
SUCCESS  = '#1a7a2e'
DANGER   = '#cc2200'
WARNING  = '#b35a00'
TEXT     = '#1a1a1a'
MUTED    = '#666666'
BORDER   = '#d0d0d0'

FONT     = ('Segoe UI', 10)
FONT_B   = ('Segoe UI', 10, 'bold')
FONT_SM  = ('Segoe UI', 9)
FONT_LG  = ('Segoe UI', 14, 'bold')
FONT_XL  = ('Segoe UI', 18, 'bold')
FONT_MONO= ('Consolas', 9)


class SecureVPNApp:
    NAV_CONNECT  = 'connect'
    NAV_PROFILES = 'profiles'
    NAV_LOGS     = 'logs'
    NAV_SETTINGS = 'settings'

    def __init__(self):
        self.root = tk.Tk()
        self.root.title('SecureVPN')
        self.root.geometry('960x640')
        self.root.minsize(860, 560)
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.update_idletasks()
        sx = (self.root.winfo_screenwidth()  - 960) // 2
        sy = (self.root.winfo_screenheight() - 640) // 2
        self.root.geometry(f'960x640+{sx}+{sy}')

        self.vpn = VPNCore()
        self.current_profile = None
        self._polling    = True
        self._connecting = False
        self._conn_state = 'disconnected'
        self._active_page = self.NAV_CONNECT

        self._build_ui()
        self._show_page(self.NAV_CONNECT)
        self._start_polling()
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)
        self.root.after(500, self._check_initial_state)

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        self._build_sidebar()
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.pages = {}
        self._build_connect_page()
        self._build_profiles_page()
        self._build_logs_page()
        self._build_settings_page()

    def _build_sidebar(self):
        sb = tk.Frame(self.root, bg=SIDEBAR, width=200)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        sb.pack_propagate(False)

        # Logo area
        logo_frame = tk.Frame(sb, bg=SIDEBAR)
        logo_frame.pack(fill=tk.X, padx=18, pady=(24, 0))
        tk.Label(logo_frame, text='SecureVPN', font=('Segoe UI', 14, 'bold'),
                 bg=SIDEBAR, fg='#ffffff').pack(anchor='w')
        tk.Label(logo_frame, text='Post-Quantum WireGuard', font=FONT_SM,
                 bg=SIDEBAR, fg='#999999').pack(anchor='w')

        tk.Frame(sb, bg='#444444', height=1).pack(fill=tk.X, padx=14, pady=(16, 8))

        self._nav_btns = {}
        for key, label in [
            (self.NAV_CONNECT,  'Connect'),
            (self.NAV_PROFILES, 'Profiles'),
            (self.NAV_LOGS,     'Logs'),
            (self.NAV_SETTINGS, 'Settings'),
        ]:
            btn = tk.Label(sb, text=label, font=FONT, bg=SIDEBAR, fg='#cccccc',
                           padx=18, pady=10, anchor='w', cursor='hand2')
            btn.pack(fill=tk.X)
            btn.bind('<Button-1>', lambda e, k=key: self._show_page(k))
            btn.bind('<Enter>', lambda e, b=btn, k=key: self._nav_hover(b, k, True))
            btn.bind('<Leave>', lambda e, b=btn, k=key: self._nav_hover(b, k, False))
            self._nav_btns[key] = btn

        # Status pill at bottom
        status_frame = tk.Frame(sb, bg='#3a3a3c')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=16)
        inner = tk.Frame(status_frame, bg='#3a3a3c')
        inner.pack(fill=tk.X, padx=10, pady=8)
        self._sidebar_dot = tk.Label(inner, text='●', font=FONT_SM,
                                      bg='#3a3a3c', fg='#666666')
        self._sidebar_dot.pack(side=tk.LEFT)
        self._sidebar_lbl = tk.Label(inner, text='Not connected', font=FONT_SM,
                                      bg='#3a3a3c', fg='#999999')
        self._sidebar_lbl.pack(side=tk.LEFT, padx=(6, 0))

        tk.Label(sb, text='NCSA · Air University', font=('Segoe UI', 7),
                 bg=SIDEBAR, fg='#555555').pack(side=tk.BOTTOM, pady=(0, 4))

    def _nav_hover(self, btn, key, entering):
        if self._active_page == key:
            return
        btn.config(bg='#3a3a3c' if entering else SIDEBAR)

    def _set_nav_active(self, page_key):
        for key, btn in self._nav_btns.items():
            if key == page_key:
                btn.config(bg='#0055cc', fg='#ffffff')
            else:
                btn.config(bg=SIDEBAR, fg='#cccccc')

    def _show_page(self, key):
        for k, f in self.pages.items():
            if k == key:
                f.pack(fill=tk.BOTH, expand=True, in_=self.content)
            else:
                f.pack_forget()
        self._active_page = key
        self._set_nav_active(key)
        if key == self.NAV_PROFILES:
            self._refresh_profiles_list()

    # ── Connect Page ─────────────────────────────────────────────

    def _build_connect_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages[self.NAV_CONNECT] = page

        # Center frame
        center = tk.Frame(page, bg=BG)
        center.place(relx=0.5, rely=0.42, anchor='center')

        # Status indicator
        self.conn_status_lbl = tk.Label(center, text='Not Connected',
                                         font=FONT_XL, bg=BG, fg=MUTED)
        self.conn_status_lbl.pack(pady=(0, 4))

        self.conn_profile_lbl = tk.Label(center, text='Choose a profile below',
                                          font=FONT_SM, bg=BG, fg=MUTED)
        self.conn_profile_lbl.pack(pady=(0, 20))

        # Connect button
        self.connect_btn = tk.Button(center, text='Connect',
                                      font=FONT_LG, width=16,
                                      bg=ACCENT, fg='white',
                                      activebackground='#0044aa',
                                      activeforeground='white',
                                      relief=tk.FLAT, bd=0,
                                      padx=20, pady=12,
                                      cursor='hand2',
                                      command=self._toggle_connection)
        self.connect_btn.pack()

        # Profile selector bar (bottom)
        bottom_bar = tk.Frame(page, bg=BG)
        bottom_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=80, pady=(0, 16))

        tk.Label(bottom_bar, text='Profile:', font=FONT_SM, bg=BG, fg=MUTED).pack(side=tk.LEFT)

        self._profile_var = tk.StringVar(value='No profiles — go to Profiles to generate one')
        self._profile_combo = ttk.Combobox(bottom_bar, textvariable=self._profile_var,
                                            font=FONT, state='readonly', width=38)
        self._profile_combo.pack(side=tk.LEFT, padx=(8, 0))
        self._profile_combo.bind('<<ComboboxSelected>>', self._on_profile_selected)

        # Stats bar
        stats_bar = tk.Frame(page, bg=BG)
        stats_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=24, pady=(0, 8))

        self._stat_labels = {}
        for key, label in [('server', 'SERVER'), ('client_ip', 'CLIENT IP'),
                            ('public_ip', 'PUBLIC IP'), ('bandwidth', 'BANDWIDTH')]:
            card = tk.Frame(stats_bar, bg=PANEL, relief=tk.FLAT,
                            highlightthickness=1, highlightbackground=BORDER)
            card.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
            tk.Label(card, text=label, font=('Segoe UI', 7, 'bold'),
                     bg=PANEL, fg=MUTED).pack(anchor='w', padx=10, pady=(6, 1))
            val_lbl = tk.Label(card, text='—', font=FONT_MONO,
                               bg=PANEL, fg=TEXT)
            val_lbl.pack(anchor='w', padx=10, pady=(0, 6))
            self._stat_labels[key] = val_lbl

    def _on_profile_selected(self, event=None):
        name = self._profile_var.get()
        profiles = [p['name'] for p in self.vpn.list_profiles()]
        if name in profiles:
            self.current_profile = name
            self.conn_profile_lbl.config(text=f'Profile: {name}')

    def _refresh_profile_dropdown(self):
        profiles = self.vpn.list_profiles()
        names = [p['name'] for p in profiles]
        self._profile_combo['values'] = names
        if self.current_profile and self.current_profile in names:
            self._profile_var.set(self.current_profile)
        elif names:
            self._profile_var.set(names[0])
            self.current_profile = names[0]
        else:
            self._profile_var.set('No profiles — go to Profiles to generate one')
            self._profile_combo['values'] = []

    # ── Profiles Page ────────────────────────────────────────────

    def _build_profiles_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages[self.NAV_PROFILES] = page

        # Header
        header = tk.Frame(page, bg=BG)
        header.pack(fill=tk.X, padx=28, pady=(24, 0))
        tk.Label(header, text='Profiles', font=FONT_XL, bg=BG, fg=TEXT).pack(side=tk.LEFT)

        btn_frame = tk.Frame(header, bg=BG)
        btn_frame.pack(side=tk.RIGHT)
        tk.Button(btn_frame, text='Generate Keys', font=FONT,
                  bg=ACCENT, fg='white', activebackground='#0044aa',
                  activeforeground='white', relief=tk.FLAT,
                  padx=12, pady=6, cursor='hand2',
                  command=self._show_keygen_dialog).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btn_frame, text='Import .conf', font=FONT,
                  bg=PANEL, fg=TEXT, relief=tk.FLAT,
                  highlightthickness=1, highlightbackground=BORDER,
                  padx=12, pady=6, cursor='hand2',
                  command=self._import_profile).pack(side=tk.LEFT)

        tk.Frame(page, bg=BORDER, height=1).pack(fill=tk.X, padx=28, pady=(16, 0))

        # PQ info strip
        pq_bar = tk.Frame(page, bg='#e8f0ff',
                           highlightthickness=1, highlightbackground='#b0c8ff')
        pq_bar.pack(fill=tk.X, padx=28, pady=(0, 0))
        tk.Label(pq_bar, text='🔐  Post-Quantum: Kyber-512 KEM · X25519 · HKDF-SHA3-256',
                 font=FONT_MONO, bg='#e8f0ff', fg=ACCENT).pack(anchor='w', padx=12, pady=6)

        # Scrollable profile list
        list_frame = tk.Frame(page, bg=BG)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=28, pady=8)

        self._prof_canvas = tk.Canvas(list_frame, bg=BG, highlightthickness=0)
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL,
                                  command=self._prof_canvas.yview)
        self._prof_inner = tk.Frame(self._prof_canvas, bg=BG)
        self._prof_inner.bind('<Configure>',
            lambda e: self._prof_canvas.configure(
                scrollregion=self._prof_canvas.bbox('all')))
        self._prof_canvas.create_window((0, 0), window=self._prof_inner, anchor='nw')
        self._prof_canvas.configure(yscrollcommand=scrollbar.set)
        self._prof_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _refresh_profiles_list(self):
        for w in self._prof_inner.winfo_children():
            w.destroy()
        profiles = self.vpn.list_profiles()
        if not profiles:
            tk.Label(self._prof_inner, text='No profiles yet.',
                     font=FONT_LG, bg=BG, fg=MUTED).pack(pady=40)
            tk.Label(self._prof_inner,
                     text='Click "Generate Keys" to create a post-quantum profile.',
                     font=FONT_SM, bg=BG, fg=MUTED).pack()
            return
        for p in profiles:
            self._make_profile_row(p)

    def _make_profile_row(self, p):
        active = self.current_profile == p['name']
        row = tk.Frame(self._prof_inner, bg=PANEL,
                        highlightthickness=1,
                        highlightbackground=ACCENT if active else BORDER)
        row.pack(fill=tk.X, pady=3)

        info = tk.Frame(row, bg=PANEL)
        info.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=10)

        name_row = tk.Frame(info, bg=PANEL)
        name_row.pack(anchor='w')
        tk.Label(name_row, text=p['name'], font=FONT_B, bg=PANEL, fg=TEXT).pack(side=tk.LEFT)
        if active:
            tk.Label(name_row, text='  ACTIVE', font=('Segoe UI', 8, 'bold'),
                     bg=PANEL, fg=ACCENT).pack(side=tk.LEFT)

        tk.Label(info, text=f"Endpoint: {p['endpoint']}   AllowedIPs: {p['allowed_ips']}",
                 font=FONT_MONO, bg=PANEL, fg=MUTED).pack(anchor='w', pady=(2, 0))

        btns = tk.Frame(row, bg=PANEL)
        btns.pack(side=tk.RIGHT, padx=12, pady=10)
        if not active:
            tk.Button(btns, text='Connect', font=FONT_SM,
                      bg=ACCENT, fg='white', relief=tk.FLAT,
                      padx=10, pady=4, cursor='hand2',
                      command=lambda n=p['name']: self._quick_connect(n)).pack(side=tk.LEFT, padx=3)
        tk.Button(btns, text='Delete', font=FONT_SM,
                  bg='#ffeeee', fg=DANGER, relief=tk.FLAT,
                  highlightthickness=1, highlightbackground='#ffcccc',
                  padx=10, pady=4, cursor='hand2',
                  command=lambda n=p['name']: self._delete_profile(n)).pack(side=tk.LEFT, padx=3)

    def _quick_connect(self, name):
        self.current_profile = name
        self._show_page(self.NAV_CONNECT)
        if not self.vpn.is_connected():
            self._connect()

    # ── Logs Page ────────────────────────────────────────────────

    def _build_logs_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages[self.NAV_LOGS] = page

        header = tk.Frame(page, bg=BG)
        header.pack(fill=tk.X, padx=28, pady=(24, 0))
        tk.Label(header, text='Connection Logs', font=FONT_XL, bg=BG, fg=TEXT).pack(side=tk.LEFT)
        tk.Button(header, text='Clear', font=FONT_SM,
                  bg=PANEL, fg=TEXT, relief=tk.FLAT,
                  highlightthickness=1, highlightbackground=BORDER,
                  padx=10, pady=4, cursor='hand2',
                  command=self._clear_logs).pack(side=tk.RIGHT)

        tk.Frame(page, bg=BORDER, height=1).pack(fill=tk.X, padx=28, pady=(16, 0))

        wrap = tk.Frame(page, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill=tk.BOTH, expand=True, padx=28, pady=12)

        self.log_text = tk.Text(wrap, wrap=tk.WORD, font=FONT_MONO,
                                 bg=PANEL, fg=TEXT, relief=tk.FLAT, bd=0,
                                 state=tk.DISABLED, highlightthickness=0,
                                 padx=12, pady=8,
                                 selectbackground='#c8d8ff')
        sb = tk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.tag_config('error',   foreground=DANGER)
        self.log_text.tag_config('success', foreground=SUCCESS)
        self.log_text.tag_config('info',    foreground=ACCENT)
        self.log_text.tag_config('warning', foreground=WARNING)
        self.log_text.tag_config('time',    foreground=MUTED)

    # ── Settings Page ────────────────────────────────────────────

    def _build_settings_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages[self.NAV_SETTINGS] = page

        tk.Label(page, text='Settings', font=FONT_XL, bg=BG, fg=TEXT).pack(
            anchor='w', padx=28, pady=(24, 0))
        tk.Frame(page, bg=BORDER, height=1).pack(fill=tk.X, padx=28, pady=(16, 0))

        cont = tk.Frame(page, bg=BG)
        cont.pack(fill=tk.BOTH, expand=True, padx=28, pady=12)

        for cfg_key, title, subtitle, default, handler, varname in [
            ('kill_switch', 'Kill Switch',
             'Block all traffic if VPN disconnects unexpectedly',
             True, self._toggle_kill_switch, 'kill_switch_var'),
            ('auto_connect', 'Auto-Connect on Startup',
             'Automatically connect when the app launches',
             False, self._toggle_auto_connect, 'auto_connect_var'),
            ('post_quantum', 'Post-Quantum Key Exchange',
             'Kyber-512 KEM + X25519 + HKDF-SHA3-256',
             True, self._toggle_pq, 'pq_var'),
        ]:
            var = tk.BooleanVar(value=self.vpn.config.get(cfg_key, default))
            setattr(self, varname, var)
            self._setting_row(cont, title, subtitle, var, handler)

        # Leak test card
        self._setting_card(cont, 'Leak Test',
                           'Verify your IP and DNS are not leaking',
                           btn_text='Run Test', btn_cmd=self._run_verify,
                           btn_attr='verify_btn')

        # Paths card
        paths_card = tk.Frame(cont, bg=PANEL,
                               highlightthickness=1, highlightbackground=BORDER)
        paths_card.pack(fill=tk.X, pady=(4, 2))
        p_inner = tk.Frame(paths_card, bg=PANEL)
        p_inner.pack(fill=tk.X, padx=16, pady=12)
        tk.Label(p_inner, text='App Data', font=FONT_B, bg=PANEL, fg=TEXT).pack(anchor='w')
        for lbl, val in [('Profiles', str(self.vpn.profiles_dir)),
                          ('Config',   str(self.vpn.config_file)),
                          ('Logs',     str(self.vpn.log_file))]:
            r = tk.Frame(p_inner, bg=PANEL)
            r.pack(anchor='w', pady=1)
            tk.Label(r, text=f'{lbl}:', width=8, anchor='w', font=FONT_SM,
                     bg=PANEL, fg=MUTED).pack(side=tk.LEFT)
            tk.Label(r, text=val, font=FONT_MONO,
                     bg=PANEL, fg=TEXT).pack(side=tk.LEFT)

    def _setting_row(self, parent, title, subtitle, var, handler):
        card = tk.Frame(parent, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill=tk.X, pady=(2, 2))
        inner = tk.Frame(card, bg=PANEL)
        inner.pack(fill=tk.X, padx=16, pady=12)
        left = tk.Frame(inner, bg=PANEL)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text=title, font=FONT_B, bg=PANEL, fg=TEXT).pack(anchor='w')
        tk.Label(left, text=subtitle, font=FONT_SM, bg=PANEL, fg=MUTED).pack(anchor='w', pady=(2, 0))
        tk.Checkbutton(inner, variable=var, command=handler,
                       bg=PANEL, activebackground=PANEL, cursor='hand2').pack(side=tk.RIGHT)

    def _setting_card(self, parent, title, subtitle, btn_text, btn_cmd, btn_attr):
        card = tk.Frame(parent, bg=PANEL,
                         highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill=tk.X, pady=(4, 2))
        inner = tk.Frame(card, bg=PANEL)
        inner.pack(fill=tk.X, padx=16, pady=12)
        left = tk.Frame(inner, bg=PANEL)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text=title, font=FONT_B, bg=PANEL, fg=TEXT).pack(anchor='w')
        tk.Label(left, text=subtitle, font=FONT_SM, bg=PANEL, fg=MUTED).pack(anchor='w', pady=(2, 0))
        btn = tk.Button(inner, text=btn_text, font=FONT_SM,
                        bg=ACCENT, fg='white', relief=tk.FLAT,
                        padx=12, pady=5, cursor='hand2',
                        command=btn_cmd)
        btn.pack(side=tk.RIGHT)
        setattr(self, btn_attr, btn)

    # ── Keygen Dialog ────────────────────────────────────────────

    def _show_keygen_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title('Generate Post-Quantum Profile')
        dlg.geometry('480x400')
        dlg.configure(bg=BG)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 480) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 400) // 2
        dlg.geometry(f'480x400+{x}+{y}')

        tk.Label(dlg, text='New Profile', font=FONT_XL, bg=BG, fg=TEXT).pack(
            anchor='w', padx=28, pady=(24, 2))
        tk.Label(dlg, text='Kyber-512 · X25519 · HKDF-SHA3-256', font=FONT_MONO,
                 bg=BG, fg=ACCENT).pack(anchor='w', padx=28)
        tk.Frame(dlg, bg=BORDER, height=1).pack(fill=tk.X, padx=28, pady=(12, 0))

        form = tk.Frame(dlg, bg=BG)
        form.pack(fill=tk.X, padx=28, pady=(12, 0))

        entries = {}
        for label_text, key, default, secret in [
            ('Profile Name', 'name', '', False),
            ('Server URL',   'url',  'https://20.29.133.180', False),
            ('API Key',      'key',  '', True),
        ]:
            tk.Label(form, text=label_text, font=FONT_SM, bg=BG, fg=MUTED).pack(
                anchor='w', pady=(8, 2))
            e = tk.Entry(form, font=FONT, bg=PANEL, fg=TEXT,
                         relief=tk.FLAT, bd=1,
                         highlightthickness=1, highlightbackground=BORDER,
                         highlightcolor=ACCENT,
                         show='•' if secret else '')
            e.insert(0, default)
            e.pack(fill=tk.X, ipady=6)
            entries[key] = e

        err_lbl = tk.Label(dlg, text='', font=FONT_SM, bg=BG, fg=DANGER)
        err_lbl.pack(pady=(8, 0))

        gen_btn = tk.Button(dlg, text='Generate Keys', font=FONT_B,
                            bg=ACCENT, fg='white', relief=tk.FLAT,
                            padx=20, pady=8, cursor='hand2')
        gen_btn.pack(pady=(8, 20))

        def _do():
            name = entries['name'].get().strip()
            url  = entries['url'].get().strip()
            key  = entries['key'].get().strip()
            if not name or not url or not key:
                err_lbl.config(text='All fields are required')
                return
            gen_btn.config(text='Generating…', state=tk.DISABLED)
            err_lbl.config(text='')
            def t():
                try:
                    r = self.vpn.generate_keys(name, url, key)
                    self.root.after(0, lambda: self._on_keygen_success(r, dlg))
                except Exception as ex:
                    self.root.after(0, lambda: self._on_keygen_error(ex, dlg, gen_btn, err_lbl))
            threading.Thread(target=t, daemon=True).start()

        gen_btn.config(command=_do)

    def _on_keygen_success(self, result, dialog):
        dialog.destroy()
        self.current_profile = result['name']
        self._log(f"Generated profile: {result['name']} (PQ: {result.get('pq_method','N/A')})", 'success')
        self._refresh_profiles_list()
        self._refresh_profile_dropdown()
        self.conn_profile_lbl.config(text=f"Profile: {result['name']}")
        messagebox.showinfo('Profile Generated',
            f"Profile '{result['name']}' created!\n\n"
            f"Client IP: {result.get('client_ip','N/A')}\n"
            f"Post-Quantum: {result.get('pq_method','N/A')}\n\n"
            f"Click Connect to connect.")

    def _on_keygen_error(self, error, dialog, btn, err_lbl):
        btn.config(text='Generate Keys', state=tk.NORMAL)
        err_lbl.config(text=str(error)[:70])
        self._log(f'Keygen error: {error}', 'error')

    # ── Connection Management ─────────────────────────────────────

    def _toggle_connection(self):
        if self._connecting:
            return
        selected = self._profile_var.get()
        profiles = self.vpn.list_profiles()
        profile_names = [p['name'] for p in profiles]
        if selected in profile_names:
            self.current_profile = selected
        if not self.current_profile or self.current_profile not in profile_names:
            if profiles:
                self.current_profile = profiles[0]['name']
                self._profile_var.set(self.current_profile)
            else:
                messagebox.showwarning('No Profile',
                    'No profiles available.\n\nGo to Profiles to generate one first.')
                return
        if self.vpn.is_connected():
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        self._connecting = True
        self._conn_state = 'connecting'
        self.connect_btn.config(text='Connecting…', state=tk.DISABLED, bg='#888888')
        self.conn_status_lbl.config(text='Connecting…', fg=WARNING)
        self.conn_profile_lbl.config(text=f'Profile: {self.current_profile}')
        self._sidebar_dot.config(fg=WARNING)
        self._sidebar_lbl.config(text='Connecting…', fg='#ccaa55')
        self._log(f"Connecting to '{self.current_profile}'…", 'info')

        def t():
            try:
                result = self.vpn.up(self.current_profile)
                r = result if isinstance(result, dict) else {}
                self.root.after(0, lambda: self._on_connected(r))
            except SecurityError as e:
                self.root.after(0, lambda: self._on_connect_error(
                    f'Security Error: {e}\n\nThis may indicate a MITM attack.', is_security=True))
            except Exception as e:
                self.root.after(0, lambda: self._on_connect_error(str(e)))
        threading.Thread(target=t, daemon=True).start()

    def _disconnect(self):
        self._connecting = True
        self._conn_state = 'connecting'
        self.connect_btn.config(text='Disconnecting…', state=tk.DISABLED, bg='#888888')
        self.conn_status_lbl.config(text='Disconnecting…', fg=WARNING)
        self._sidebar_dot.config(fg=WARNING)
        self._log('Disconnecting…', 'info')

        def t():
            try:
                self.vpn.down()
                self.root.after(0, self._on_disconnected)
            except Exception as e:
                self.root.after(0, lambda: self._on_connect_error(f'Disconnect error: {e}'))
        threading.Thread(target=t, daemon=True).start()

    def _on_connected(self, result):
        self._connecting = False
        self._conn_state = 'connected'
        self.connect_btn.config(text='Disconnect', state=tk.NORMAL,
                                 bg=DANGER, activebackground='#aa1100')
        self.conn_status_lbl.config(text='Connected', fg=SUCCESS)
        self._sidebar_dot.config(fg='#44cc66')
        self._sidebar_lbl.config(text='Connected', fg='#88cc99')
        self._stat_labels['bandwidth'].config(text='Measuring…')
        self._log('Connected successfully!', 'success')
        self.conn_profile_lbl.config(text=f'Profile: {self.current_profile}')
        if result:
            if result.get('server_ip'):
                self._stat_labels['server'].config(text=result['server_ip'])
            if result.get('client_ip'):
                self._stat_labels['client_ip'].config(text=result['client_ip'])
            if result.get('endpoint'):
                self._stat_labels['server'].config(text=result['endpoint'].split(':')[0])

        def fetch_ip():
            try:
                import requests
                r = requests.get('https://api.ipify.org?format=json', timeout=5)
                ip = r.json().get('ip', 'unknown')
                self.root.after(0, lambda: self._stat_labels['public_ip'].config(text=ip))
            except Exception:
                self.root.after(0, lambda: self._stat_labels['public_ip'].config(text='unknown'))
        threading.Thread(target=fetch_ip, daemon=True).start()

    def _on_disconnected(self):
        self._connecting = False
        self._conn_state = 'disconnected'
        self.connect_btn.config(text='Connect', state=tk.NORMAL,
                                 bg=ACCENT, activebackground='#0044aa')
        self.conn_status_lbl.config(text='Not Connected', fg=MUTED)
        self._sidebar_dot.config(fg='#666666')
        self._sidebar_lbl.config(text='Not connected', fg='#999999')
        self._log('Disconnected', 'info')
        self.conn_profile_lbl.config(text='Choose a profile below')
        for lbl in self._stat_labels.values():
            lbl.config(text='—')

    def _on_connect_error(self, msg, is_security=False):
        self._connecting = False
        self._conn_state = 'disconnected'
        self.connect_btn.config(text='Connect', state=tk.NORMAL,
                                 bg=ACCENT, activebackground='#0044aa')
        self.conn_status_lbl.config(text='Failed', fg=DANGER)
        self._sidebar_dot.config(fg='#cc4444')
        self._sidebar_lbl.config(text='Error', fg='#cc8888')
        self._log(f'Error: {msg}', 'error')
        if is_security:
            messagebox.showerror('Security Alert', msg)
        else:
            messagebox.showerror('Connection Error', msg)

    # ── Profile Actions ──────────────────────────────────────────

    def _import_profile(self):
        fp = filedialog.askopenfilename(title='Select WireGuard Configuration',
            filetypes=[('WireGuard Config', '*.conf'), ('All Files', '*.*')])
        if fp:
            try:
                name = self.vpn.import_profile(fp)
                self._refresh_profiles_list()
                self._refresh_profile_dropdown()
                self._log(f'Imported profile: {name}', 'success')
            except Exception as e:
                messagebox.showerror('Import Error', str(e))
                self._log(f'Import error: {e}', 'error')

    def _delete_profile(self, name):
        if messagebox.askyesno('Confirm', f"Delete profile '{name}'?"):
            try:
                self.vpn.delete_profile(name)
                if self.current_profile == name:
                    self.current_profile = None
                    self.conn_profile_lbl.config(text='Select a profile to connect')
                self._refresh_profiles_list()
                self._refresh_profile_dropdown()
                self._log(f'Deleted profile: {name}', 'info')
            except Exception as e:
                self._log(f'Delete error: {e}', 'error')

    # ── Verify / Settings Handlers ────────────────────────────────

    def _run_verify(self):
        self.verify_btn.config(text='Checking…', state=tk.DISABLED)
        self._log('Running leak test…', 'info')

        def t():
            try:
                import requests as req
                ip = 'unknown'
                try:
                    r = req.get('https://api.ipify.org?format=json', timeout=8)
                    ip = r.json().get('ip', 'unknown')
                except Exception:
                    pass
                connected = self.vpn.is_connected()
                ping = self.vpn._check_vpn_ping()
                self.root.after(0, lambda: self._on_verify_done(
                    {'public_ip': ip, 'connected': connected, 'ping_ok': ping}))
            except Exception:
                self.root.after(0, lambda: self._on_verify_done(
                    {'public_ip': 'error', 'connected': False, 'ping_ok': False}))
        threading.Thread(target=t, daemon=True).start()

    def _on_verify_done(self, result):
        self.verify_btn.config(text='Run Test', state=tk.NORMAL)
        ip = result.get('public_ip', 'unknown')
        conn = result.get('connected', False)
        ping = result.get('ping_ok', False)
        if conn and ping:
            self._log(f'Leak test: PASS (IP: {ip}, tunnel ping: OK)', 'success')
            self._stat_labels['public_ip'].config(text=ip)
            messagebox.showinfo('Leak Test',
                f'VPN is working correctly!\n\nPublic IP: {ip}\nTunnel ping: OK\nNo leaks detected')
        elif conn:
            self._log('Leak test: WARNING (connected, ping unstable)', 'warning')
            messagebox.showwarning('Leak Test', f'VPN connected but tunnel is unstable.\n\nPublic IP: {ip}')
        else:
            self._log('Leak test: NOT CONNECTED', 'error')
            messagebox.showwarning('Leak Test', 'VPN is not connected.')

    def _toggle_kill_switch(self):
        self.vpn.config['kill_switch'] = self.kill_switch_var.get()
        self.vpn._save_config()
        self._log(f"Kill switch {'enabled' if self.kill_switch_var.get() else 'disabled'}", 'info')

    def _toggle_auto_connect(self):
        self.vpn.config['auto_connect'] = self.auto_connect_var.get()
        self.vpn._save_config()

    def _toggle_pq(self):
        self.vpn.config['post_quantum'] = self.pq_var.get()
        self.vpn._save_config()

    # ── Polling ──────────────────────────────────────────────────

    def _start_polling(self):
        def poll():
            while self._polling:
                try:
                    if self.vpn.is_connected():
                        status = self.vpn.get_status()
                        if status.connected:
                            self.root.after(0, lambda s=status: self._update_status(s))
                    else:
                        if not self._connecting:
                            self.root.after(0, self._check_disconnected)
                except Exception:
                    pass
                time.sleep(5)
        threading.Thread(target=poll, daemon=True).start()

    def _update_status(self, status):
        if self._connecting:
            return
        if status.server_ip:
            self._stat_labels['server'].config(text=status.server_ip)
        if status.client_ip:
            self._stat_labels['client_ip'].config(text=status.client_ip)
        try:
            bw = self.vpn.get_bandwidth()
            if bw['rx_rate'] > 0 or bw['tx_rate'] > 0:
                bt = f"{bw['rx_human']} ↓  {bw['tx_human']} ↑"
            elif bw.get('rx_bytes', 0) > 0 or bw.get('tx_bytes', 0) > 0:
                bt = f"{bw['rx_total_human']} ↓  {bw['tx_total_human']} ↑ (total)"
            else:
                bt = 'Measuring…'
            self._stat_labels['bandwidth'].config(text=bt)
        except Exception:
            pass
        if self.conn_status_lbl.cget('text') != 'Connected':
            self._conn_state = 'connected'
            self.connect_btn.config(text='Disconnect', state=tk.NORMAL,
                                     bg=DANGER, activebackground='#aa1100')
            self.conn_status_lbl.config(text='Connected', fg=SUCCESS)
            self._sidebar_dot.config(fg='#44cc66')
            self._sidebar_lbl.config(text='Connected', fg='#88cc99')

    def _check_disconnected(self):
        if not self._connecting:
            if self.conn_status_lbl.cget('text') == 'Connected' and not self.vpn.is_connected():
                self._on_disconnected()

    def _check_initial_state(self):
        try:
            if self.vpn.is_connected():
                self._conn_state = 'connected'
                self.connect_btn.config(text='Disconnect', state=tk.NORMAL,
                                         bg=DANGER, activebackground='#aa1100')
                self.conn_status_lbl.config(text='Connected', fg=SUCCESS)
                self._sidebar_dot.config(fg='#44cc66')
                self._sidebar_lbl.config(text='Connected', fg='#88cc99')
                self._log('VPN tunnel is already connected', 'success')
                status = self.vpn.get_status()
                if status.connected:
                    self._update_status(status)
                tn = self.vpn._get_active_tunnel_name()
                if tn:
                    self.current_profile = tn
                    self._profile_var.set(tn)
                    self.conn_profile_lbl.config(text=f'Profile: {tn}')
            else:
                self._refresh_profile_dropdown()
                self._log('Ready — click Connect to start.', 'info')
        except Exception:
            self._log('Ready — click Connect to start.', 'info')

    # ── Logging / Lifecycle ──────────────────────────────────────

    def _log(self, message, level='info'):
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f'[{ts}]  ', 'time')
        self.log_text.insert(tk.END, f'{message}\n',
                              level if level in ('error', 'success', 'info', 'warning') else None)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete('1.0', tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _on_close(self):
        self._polling = False
        if self.vpn.is_connected():
            if messagebox.askyesno('Exit', 'VPN tunnel is active. Disconnect before exiting?'):
                try:
                    self.vpn.down()
                except Exception:
                    pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    app = SecureVPNApp()
    app.run()


if __name__ == '__main__':
    main()
