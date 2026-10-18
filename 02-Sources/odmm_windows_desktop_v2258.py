"""ODMM Desktop: read-only Windows client, not a migration agent."""
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.parse import urlsplit
import webbrowser
from odmm_desktop_model_v2258 import read_report, report_summary, pretty_report
from odmm_desktop_preflight_v2260 import inspect_local_source

VERSION = 'V226.0 / Compact V7.7.0'
AUTHOR = 'Abdelhalim Talbi'

def valid_console_url(url):
    try:
        p = urlsplit(url.strip())
        return (p.scheme == 'https' or (p.scheme == 'http' and p.hostname in ('localhost', '127.0.0.1', '::1'))) and bool(p.hostname) and not p.username and not p.password and p.path in ('', '/') and not p.query and not p.fragment
    except ValueError:
        return False

def main():
    root = tk.Tk()
    root.title('ODMM Desktop | ' + VERSION)
    root.geometry('1060x720')
    root.minsize(800, 540)
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except tk.TclError:
        pass
    style.configure('Heading.TLabel', font=('Segoe UI', 19, 'bold'))
    style.configure('Sub.TLabel', font=('Segoe UI', 10))
    body = ttk.Frame(root, padding=20)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text='ODMM  /  Open Data Migration Manager', style='Heading.TLabel').pack(anchor='w')
    ttk.Label(body, text='Console Desktop · ' + VERSION + ' · ' + AUTHOR, style='Sub.TLabel').pack(anchor='w', pady=(3, 12))
    tabs = ttk.Notebook(body)
    tabs.pack(fill='both', expand=True)
    overview = ttk.Frame(tabs, padding=18)
    tabs.add(overview, text='Vue d’ensemble')
    ttk.Label(overview, text='Pilotage centralisé, sans opération implicite', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
    ttk.Label(overview, text='Ce client affiche les rapports locaux et ouvre la console Web ODMM. Le serveur, OIDC, les migrations et le cutover sont distincts.', wraplength=850).pack(anchor='w', pady=(8, 20))
    for name, desc in (
        ('1  Préparer', 'Valider la connectivité, les identités et les droits dans la console Web.'),
        ('2  Planifier', 'Sélectionner les sources/cibles et vérifier les contraintes NFS, SMB et ACL côté serveur.'),
        ('3  Exécuter', 'Lancer les migrations depuis le serveur ODMM authentifié, jamais depuis ce client de consultation.'),
        ('4  Vérifier', 'Consulter les preuves d’intégrité, les rapports et les décisions de bascule explicites.'),
    ):
        box = ttk.LabelFrame(overview, text=name, padding=10)
        box.pack(fill='x', pady=5)
        ttk.Label(box, text=desc, wraplength=850).pack(anchor='w')
    planning = ttk.Frame(tabs, padding=18)
    tabs.add(planning, text='Préparer une migration')
    ttk.Label(planning, text='Inventaire local en lecture seule — aucune copie ni bascule', font=('Segoe UI', 12, 'bold')).pack(anchor='w')
    paths = {}
    for label, key in (('Répertoire source', 'source'), ('Répertoire cible', 'target')):
        ttk.Label(planning, text=label).pack(anchor='w', pady=(10, 0))
        line = ttk.Frame(planning)
        line.pack(fill='x')
        value = tk.StringVar()
        paths[key] = value
        ttk.Entry(line, textvariable=value).pack(side='left', fill='x', expand=True)
        ttk.Button(line, text='Parcourir', command=lambda v=value: v.set(filedialog.askdirectory() or v.get())).pack(side='left', padx=8)
    preflight_out = tk.Text(planning, height=13, wrap='word', font=('Consolas', 10))
    preflight_out.pack(fill='both', expand=True, pady=12)
    def run_preflight():
        try:
            result = inspect_local_source(paths['source'].get(), paths['target'].get())
            preflight_out.delete('1.0', 'end')
            preflight_out.insert('end', json.dumps(result, indent=2, ensure_ascii=False))
        except (OSError, ValueError) as exc:
            messagebox.showerror('Précontrôle bloqué', str(exc))
    ttk.Button(planning, text='Analyser sans modifier', command=run_preflight).pack(anchor='w')
    ttk.Label(planning, text='Le contrôle des ACL, des identités et le transfert réel restent réservés au moteur ODMM authentifié.').pack(anchor='w', pady=8)
    console = ttk.Frame(tabs, padding=18)
    tabs.add(console, text='Console sécurisée')
    ttk.Label(console, text='Adresse du serveur ODMM (HTTPS, ou HTTP en loopback uniquement)').pack(anchor='w')
    url = tk.StringVar(value='https://localhost:8443')
    ttk.Entry(console, textvariable=url, width=95).pack(fill='x', pady=10)
    def open_console():
        if not valid_console_url(url.get()):
            messagebox.showerror('Adresse refusée', 'HTTPS requis hors loopback ; identifiants, chemins et paramètres interdits dans l’URL.')
            return
        webbrowser.open(url.get().strip().rstrip('/') + '/operations')
    ttk.Button(console, text='Ouvrir la console Web authentifiée', command=open_console).pack(anchor='w')
    ttk.Label(console, text='L’authentification et les autorisations sont appliquées par le serveur ODMM.', wraplength=850).pack(anchor='w', pady=12)
    reports = ttk.Frame(tabs, padding=18)
    tabs.add(reports, text='Rapports et audit')
    summary = tk.StringVar(value='Aucun rapport chargé')
    ttk.Label(reports, textvariable=summary).pack(anchor='w')
    controls = ttk.Frame(reports)
    controls.pack(fill='x', pady=8)
    search = tk.StringVar()
    ttk.Label(controls, text='Filtrer les lignes :').pack(side='left')
    ttk.Entry(controls, textvariable=search).pack(side='left', fill='x', expand=True, padx=8)
    txt = tk.Text(reports, wrap='none', height=16, font=('Consolas', 10))
    txt.pack(fill='both', expand=True)
    data_holder = {'data': None}
    def refresh(*_):
        if data_holder['data'] is None:
            return
        txt.delete('1.0', 'end')
        txt.insert('end', pretty_report(data_holder['data'], search.get()))
    search.trace_add('write', refresh)
    def load_report():
        path = filedialog.askopenfilename(title='Lire un rapport ODMM', filetypes=[('JSON', '*.json')])
        if not path:
            return
        try:
            data = read_report(path)
            data_holder['data'] = data
            details = report_summary(data)
            summary.set(f"Rapport chargé · {details['format']} · {details['entries']} éléments · statut déclaré : {details['status']}")
            refresh()
        except (OSError, ValueError, UnicodeError) as exc:
            messagebox.showerror('Rapport non chargé', str(exc))
    ttk.Button(reports, text='Ouvrir un rapport JSON', command=load_report).pack(anchor='w', pady=8)
    about = ttk.Frame(tabs, padding=18)
    tabs.add(about, text='À propos / sécurité')
    ttk.Label(about, text=f'ODMM {VERSION}\nAuteur : {AUTHOR}\n\nClient Windows de consultation uniquement.\nAucun accès NAS direct, aucune authentification contournée, aucun fallback silencieux, aucune bascule automatique.\n\nLe moteur natif reste le moteur prioritaire des services ODMM Full et Compact.', justify='left', wraplength=850).pack(anchor='w')
    root.mainloop()

if __name__ == '__main__':
    main()
