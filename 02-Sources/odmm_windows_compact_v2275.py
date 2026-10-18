"""ODMM Compact Windows — lightweight read-only supervisor, no migration execution."""
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from odmm_registry_client_v2267 import fetch_registry_jobs
from odmm_desktop_model_v2258 import read_report, report_summary
from odmm_compact_model_v2275 import filter_rows, summarize_rows

VERSION = "7.8.5"
AUTHOR = "Abdelhalim Talbi"

def main():
    root = tk.Tk()
    root.title("ODMM Compact Windows V" + VERSION)
    root.geometry("920x640")
    root.minsize(680, 450)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)
    head = ttk.Frame(root, padding=14)
    head.grid(row=0, column=0, sticky="ew")
    ttk.Label(head, text="ODMM Compact", font=("Segoe UI", 20, "bold")).pack(anchor="w")
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
    rows = []
    inbox = queue.Queue()
    generation = [0]
    closed = [False]
    def refresh_table(*_):
        for item in tree.get_children(): tree.delete(item)
        visible = filter_rows(rows, search.get(), state.get())
        for row in visible:
            tree.insert("", "end", values=(row.get("id", ""), row.get("status", "")))
        c = summarize_rows(rows)
        summary.set(f"Total : {c['total']}    En cours : {c['running']}    Échecs : {c['failed']}    Terminés : {c['completed']}")
    def load():
        generation[0] += 1
        request_id = generation[0]
        endpoint, bearer = origin.get(), token.get()
        status.set("Connexion en cours…")
        load_button.configure(state="disabled")
        def worker():
            try: inbox.put((request_id, fetch_registry_jobs(endpoint, bearer), None))
            except Exception as exc: inbox.put((request_id, None, type(exc).__name__ + " : " + str(exc)))
        threading.Thread(target=worker, daemon=True).start()
    load_button = ttk.Button(connection, text="Actualiser les jobs", command=load)
    load_button.grid(row=2, column=1, sticky="e", pady=6)
    filters = ttk.Frame(jobs)
    filters.grid(row=1, column=0, sticky="ew", pady=10)
    search = tk.StringVar()
    state = tk.StringVar(value="ALL")
    ttk.Label(filters, text="Rechercher").pack(side="left")
    ttk.Entry(filters, textvariable=search, width=25).pack(side="left", padx=6)
    ttk.Label(filters, text="État").pack(side="left", padx=(10, 0))
    ttk.Combobox(filters, textvariable=state, values=("ALL", "RUNNING", "FAILED", "PENDING", "COMPLETED", "UNKNOWN"), state="readonly", width=13).pack(side="left", padx=6)
    search.trace_add("write", refresh_table)
    state.trace_add("write", refresh_table)
    summary = tk.StringVar(value="Total : 0")
    ttk.Label(jobs, textvariable=summary, font=("Segoe UI", 11, "bold")).grid(row=2, column=0, sticky="w")
    tree = ttk.Treeview(jobs, columns=("id", "status"), show="headings")
    tree.heading("id", text="Migration / Job")
    tree.heading("status", text="État")
    tree.column("id", width=480)
    tree.column("status", width=180)
    tree.grid(row=3, column=0, sticky="nsew", pady=8)
    ttk.Label(jobs, textvariable=status, wraplength=750).grid(row=4, column=0, sticky="w")
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
                if error: status.set("Échec de consultation : " + error)
                else:
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
    root.after(80, drain)
    root.mainloop()

if __name__ == "__main__": main()
