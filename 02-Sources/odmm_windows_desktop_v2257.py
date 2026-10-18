"""ODMM Windows desktop shell (read-only). No implicit authentication or cutover."""
import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from urllib.parse import urlsplit
import webbrowser

VERSION='V225.7 / Compact V7.6.7'
AUTHOR='Abdelhalim Talbi'


def valid_console_url(url):
    """Allow HTTPS or loopback HTTP only; reject credentials and non-root paths."""
    try:
        p=urlsplit(url.strip())
        return (p.scheme=='https' or (p.scheme=='http' and p.hostname in ('localhost','127.0.0.1','::1'))) and bool(p.hostname) and not p.username and not p.password and p.path in ('','/') and not p.query and not p.fragment
    except ValueError:
        return False


def main():
    root=tk.Tk(); root.title('ODMM | Console Windows — '+VERSION); root.geometry('940x620'); root.minsize(740,470)
    style=ttk.Style(root)
    try: style.theme_use('clam')
    except tk.TclError: pass
    outer=ttk.Frame(root,padding=22); outer.pack(fill='both',expand=True)
    ttk.Label(outer,text='ODMM · Open Data Migration Manager',font=('Segoe UI',19,'bold')).pack(anchor='w')
    ttk.Label(outer,text='Full + Compact  |  '+VERSION+'  |  '+AUTHOR).pack(anchor='w',pady=(5,15))
    tabs=ttk.Notebook(outer); tabs.pack(fill='both',expand=True)
    home=ttk.Frame(tabs,padding=20); tabs.add(home,text='Accueil')
    ttk.Label(home,text='Console de lancement et diagnostic — aucune migration automatique',font=('Segoe UI',12,'bold')).pack(anchor='w',pady=(0,15))
    ttk.Label(home,text='URL de votre serveur ODMM authentifié (HTTPS requis hors machine locale) :').pack(anchor='w')
    url=tk.StringVar(value='https://localhost:8443')
    ttk.Entry(home,textvariable=url,width=80).pack(fill='x',pady=7)
    def open_console():
        if not valid_console_url(url.get()):
            messagebox.showerror('URL non autorisée','Utilisez HTTPS ou HTTP en loopback uniquement, sans identifiants dans l’URL.'); return
        webbrowser.open(url.get().rstrip('/')+'/operations')
    ttk.Button(home,text='Ouvrir la console Web sécurisée',command=open_console).pack(anchor='w',pady=8)
    ttk.Label(home,text='Le serveur ODMM, son identité OIDC et ses autorisations doivent être configurés séparément.',wraplength=750).pack(anchor='w',pady=8)
    audit=ttk.Frame(tabs,padding=20);tabs.add(audit,text='Audit local')
    txt=tk.Text(audit,wrap='word',height=18);txt.pack(fill='both',expand=True)
    def load_report():
        path=filedialog.askopenfilename(title='Ouvrir un rapport ODMM',filetypes=[('Rapports JSON','*.json'),('Tous les fichiers','*.*')]);
        if not path:return
        try:
            if Path(path).stat().st_size>5_000_000: raise ValueError('Rapport trop volumineux (limite 5 Mo)')
            data=json.loads(Path(path).read_text(encoding='utf-8'))
            txt.delete('1.0','end');txt.insert('end',json.dumps(data,ensure_ascii=False,indent=2))
        except (OSError,ValueError) as e:messagebox.showerror('Rapport illisible',str(e))
    ttk.Button(audit,text='Ouvrir un rapport JSON (lecture seule)',command=load_report).pack(anchor='w',pady=8)
    info=ttk.Frame(tabs,padding=20);tabs.add(info,text='Sécurité / À propos')
    ttk.Label(info,text='ODMM — '+VERSION+'\nAuteur : '+AUTHOR+'\n\nCette application est un client de consultation et un lecteur de rapports.\nElle ne contient pas le serveur, ne contourne pas OIDC, ne lance pas de migration\net n’autorise jamais le cutover.\n\nLes moteurs de migration Full et Compact restent distribués séparément.',justify='left').pack(anchor='w')
    root.mainloop()
if __name__=='__main__':main()
