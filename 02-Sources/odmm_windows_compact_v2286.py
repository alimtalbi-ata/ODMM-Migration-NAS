"""ODMM Compact Windows — lightweight read-only supervisor, no migration execution."""
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from odmm_registry_client_v2267 import fetch_registry_jobs
from odmm_desktop_model_v2258 import read_report, report_summary
from odmm_compact_dashboard_v2280 import dashboard
from odmm_attention_v2281 import attention_summary
from odmm_health_v2283 import assess
from odmm_payload_gate_v2285 import validate_jobs
from odmm_job_detail_v2279 import select_job as find_job_by_id
from odmm_job_triage_v2280 import triage_job, triage_lines

VERSION = "7.9.6"
AUTHOR = "Abdelhalim Talbi"

def main():
    root = tk.Tk()
    root.title("Open Data Migration Manager — Windows Compact V" + VERSION)
    root.geometry("1020x700")
    root.minsize(760, 500)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)
    head = ttk.Frame(root, padding=14)
    head.grid(row=0, column=0, sticky="ew")
    ttk.Label(head, text="Open Data Migration Manager", font=("Segoe UI", 20, "bold")).pack(anchor="w")
    ttk.Label(head, text="Suivre les migrations · consulter les rapports · lecture seule", font=("Segoe UI", 10)).pack(anchor="w")
    tabs = ttk.Notebook(root)
    tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 10))
    jobs = ttk.Frame(tabs, padding=12)
    reports = ttk.Frame(tabs, padding=12)
    about = ttk.Frame(tabs, padding=12)
    tabs.add(jobs, text="Suivre les migrations")
    tabs.add(reports, text="Rapports")
    tabs.add(about, text="À propos")
    for tab in (jobs, reports): tab.columnconfigure(0, weight=1)
    jobs.rowconfigure(3, weight=1)
    jobs.columnconfigure(0, weight=1)
    connection = ttk.LabelFrame(jobs, text="Connexion au serveur ODMM", padding=8)
    connection.grid(row=0, column=0, sticky="ew")
    connection.columnconfigure(1, weight=1)
    origin = tk.StringVar(value="http://127.0.0.1:8090")
    token = tk.StringVar()
    ttk.Label(connection, text="Adresse").grid(row=0, column=0, sticky="w")
    ttk.Entry(connection, textvariable=origin).grid(row=0, column=1, sticky="ew", padx=8)
    ttk.Label(connection, text="Jeton").grid(row=1, column=0, sticky="w")
    ttk.Entry(connection, textvariable=token, show="•").grid(row=1, column=1, sticky="ew", padx=8)
    status = tk.StringVar(value="Prêt — aucune action de migration n'est déclenchée")
    detail = tk.StringVar(value="Sélectionnez un job pour afficher sa fiche de migration.")
    rows = []
    inbox = queue.Queue()
    generation = [0]
    closed = [False]
    def refresh_table(*_):
        selected_ids = {tree.item(item, "values")[0] for item in tree.selection() if tree.item(item, "values")}
        for item in tree.get_children(): tree.delete(item)
        view = dashboard(rows, search.get(), state.get())
        visible = view["jobs"]
        for row in visible:
            item = tree.insert("", "end", values=(row.get("id", ""), row.get("status", "")))
            if str(row.get("id", "")) in selected_ids:
                tree.selection_add(item)
        c = view["visible"]
        overall = view["total"]
        a = attention_summary(rows)
        health = assess(rows)
        summary.set(f"Total : {overall['total']}  |  En cours : {overall['running']}  |  Échecs : {a['failed']}  |  À examiner : {a['needs_attention']}  |  Affichés : {c['total']}  |  Diagnostic : {health['level']}")
        if not tree.selection():
            detail.set("Sélectionnez un job pour afficher son identifiant et son état.")
        else:
            select_job()
    def load():
        generation[0] += 1
        request_id = generation[0]
        endpoint, bearer = origin.get(), token.get()
        status.set("Connexion en cours…")
        detail.set("Actualisation en cours…")
        load_button.configure(state="disabled")
        def worker():
            try: inbox.put((request_id, fetch_registry_jobs(endpoint, bearer), None))
            except Exception as exc: inbox.put((request_id, None, type(exc).__name__))
        threading.Thread(target=worker, daemon=True).start()
    load_button = ttk.Button(connection, text="Actualiser les jobs", command=load)
    load_button.grid(row=2, column=1, sticky="e", pady=6)
    filters = ttk.Frame(jobs)
    filters.grid(row=1, column=0, sticky="ew", pady=10)
    search = tk.StringVar()
    state = tk.StringVar(value="ALL")
    ttk.Label(filters, text="Rechercher").pack(side="left")
    search_entry = ttk.Entry(filters, textvariable=search, width=25)
    search_entry.pack(side="left", padx=6)
    ttk.Label(filters, text="État").pack(side="left", padx=(10, 0))
    ttk.Combobox(filters, textvariable=state, values=("ALL", "RUNNING", "FAILED", "PENDING", "COMPLETED", "UNKNOWN"), state="readonly", width=13).pack(side="left", padx=6)
    search.trace_add("write", refresh_table)
    state.trace_add("write", refresh_table)
    summary = tk.StringVar(value="Aucune donnée chargée")
    ttk.Label(jobs, textvariable=summary, font=("Segoe UI", 11, "bold")).grid(row=2, column=0, sticky="w")
    ttk.Button(filters, text="Voir les échecs", command=lambda: (search.set(""), state.set("FAILED"))).pack(side="left", padx=6)
    ttk.Button(filters, text="Tous les jobs", command=lambda: (search.set(""), state.set("ALL"))).pack(side="left")
    tree = ttk.Treeview(jobs, columns=("id", "status"), show="headings")
    tree.heading("id", text="Migration / Job")
    tree.heading("status", text="État")
    tree.column("id", width=480)
    tree.column("status", width=180)
    tree.grid(row=3, column=0, sticky="nsew", pady=8)
    ttk.Label(jobs, textvariable=detail, wraplength=750, justify="left").grid(row=4, column=0, sticky="w")
    ttk.Label(jobs, textvariable=status, wraplength=750).grid(row=5, column=0, sticky="w", pady=(4, 0))
    def select_job(_event=None):
        chosen = tree.selection()
        if not chosen:
            detail.set("Sélectionnez un job pour afficher son identifiant et son état.")
            return
        values = tree.item(chosen[0], "values")
        try:
            selected = find_job_by_id(rows, values[0])
            detail.set("Fiche de migration (lecture seule)\n" + "\n".join(triage_lines(triage_job(selected["fields"]))))
        except ValueError:
            detail.set("Fiche indisponible : identifiant absent ou non unique")
    tree.bind("<<TreeviewSelect>>", select_job)
    root.bind("<Control-r>", lambda _e: load() if str(load_button.cget("state")) != "disabled" else None)
    root.bind("<Control-f>", lambda _e: search_entry.focus_set())
    report_status = tk.StringVar(value="Ouvrir un rapport JSON existant ; aucune modification du fichier")
    ttk.Label(reports, textvariable=report_status, wraplength=750).grid(row=0, column=0, sticky="w")
    def open_report():
        path = filedialog.askopenfilename(filetypes=[("Rapports JSON", "*.json")])
        if not path: return
        try:
            data = read_report(path)
            s = report_summary(data)
            report_status.set(f"{path} — {s['format']}, {s['entries']} entrées, état : {s['status']}")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Rapport non lisible", str(exc))
    ttk.Button(reports, text="Ouvrir un rapport JSON", command=open_report).grid(row=1, column=0, sticky="w", pady=12)
    ttk.Label(about, text="ODMM Compact Windows V" + VERSION + "\nAuteur : " + AUTHOR + "\n\nClient léger en lecture seule.\nAucune copie, modification ACL, bascule ou migration depuis ce programme.\nLes opérations réelles sont exécutées par le serveur ODMM.", justify="left", wraplength=650).pack(anchor="w")
    def drain():
        if closed[0]: return
        try:
            while True:
                rid, data, error = inbox.get_nowait()
                if rid != generation[0]: continue
                load_button.configure(state="normal")
                if error:
                    status.set("Échec de consultation : " + error)
                    detail.set("Données précédentes conservées ; vérifier la connexion et le jeton.")
                else:
                    if not isinstance(data, list) or any(not isinstance(r, dict) for r in data):
                        status.set("Réponse serveur invalide : registre non conforme")
                        detail.set("Données précédentes conservées ; aucune modification distante.")
                        continue
                    try:
                        validate_jobs(data)
                    except ValueError:
                        status.set("Registre ambigu : identifiants ou états non conformes")
                        detail.set("Données précédentes conservées ; contacter l’administrateur du serveur.")
                        continue
                    rows.clear()
                    rows.extend(data)
                    refresh_table()
                    status.set("Consultation terminée — lecture seule")
        except queue.Empty: pass
        root.after(80, drain)
    def close():
        closed[0] = True
        generation[0] += 1
        token.set("")
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    root.bind("<Escape>", lambda _e: close())
    root.after(80, drain)
    root.mainloop()

if __name__ == "__main__": main()
