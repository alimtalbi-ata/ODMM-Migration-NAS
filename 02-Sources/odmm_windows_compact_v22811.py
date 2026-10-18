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
from odmm_supervision_v2287 import supervision, overview_lines
from odmm_job_detail_v2279 import select_job as find_job_by_id
from odmm_job_triage_v2280 import triage_job, triage_lines
from odmm_ui_state_v22811 import resolve_refresh, selection_after_filter
from odmm_connection_diagnostics_v22851 import explain_connection_failure
from odmm_ui_diagnostics_v22858 import refresh_message, safe_count
from odmm_pagination_v22859 import paginate, sort_jobs
from odmm_refresh_guard_v22860 import server_limit_notice

VERSION = "7.9.29"  # Product version for cumulative delivery V228.74
AUTHOR = "Abdelhalim Talbi"

def main():
    root = tk.Tk()
    root.title("Open Data Migration Manager — Windows Compact V" + VERSION)
    root.geometry("1120x740")
    root.minsize(900, 600)
    style = ttk.Style(root)
    if "vista" in style.theme_names(): style.theme_use("vista")
    style.configure("Treeview", rowheight=27)
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
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
    tabs.enable_traversal()  # Ctrl+Tab / Ctrl+Shift+Tab navigation
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
    ttk.Label(connection, text="Jeton API").grid(row=1, column=0, sticky="w")
    ttk.Entry(connection, textvariable=token, show="•").grid(row=1, column=1, sticky="ew", padx=8)
    ttk.Label(connection, text="Le jeton reste en mémoire et n’est jamais exporté.").grid(row=3, column=1, sticky="w")
    status = tk.StringVar(value="Prêt — aucune action de migration n'est déclenchée")
    detail = tk.StringVar(value="Sélectionnez un job pour afficher sa fiche de migration.")
    rows = []
    inbox = queue.Queue(maxsize=0)  # no blocking worker on completed/stale requests
    generation = [0]
    closed = [False]
    page_index = [0]
    page_size = 200
    def refresh_table(*_):
        selected_ids = {str(tree.item(item, "values")[0]) for item in tree.selection() if tree.item(item, "values")}
        for item in tree.get_children(): tree.delete(item)
        view = dashboard(rows, search.get(), state.get())
        visible = sort_jobs(view["jobs"], sort_state["column"], sort_state["reverse"])
        page_rows, page_number, page_count = paginate(visible, page_index[0], page_size)
        page_index[0] = page_number
        page_label.set(f"Page {page_number + 1} / {page_count} · {len(visible)} résultats filtrés")
        previous_button.configure(state="normal" if page_number > 0 else "disabled")
        next_button.configure(state="normal" if page_number + 1 < page_count else "disabled")
        for row in page_rows:
            normalized_status = str(row.get("status", "UNKNOWN")).strip().upper()
            item = tree.insert("", "end", values=(row.get("id", ""), row.get("status", "")),
                               tags=(normalized_status if normalized_status in {"FAILED", "RUNNING", "COMPLETED", "PENDING"} else "UNKNOWN",))
            if str(row.get("id", "")) in selection_after_filter(selected_ids, visible):
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
        while not inbox.empty():
            try: inbox.get_nowait()
            except queue.Empty: break
        endpoint, bearer = origin.get(), token.get()
        status.set("Connexion en cours…")
        detail.set("Actualisation en cours…")
        load_button.configure(state="disabled")
        def worker():
            try:
                result = fetch_registry_jobs(endpoint, bearer)
                inbox.put((request_id, result, None))
            except Exception as exc:
                inbox.put((request_id, None, explain_connection_failure(exc)))
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
    search_entry.configure(takefocus=True)
    ttk.Label(filters, text="État").pack(side="left", padx=(10, 0))
    ttk.Combobox(filters, textvariable=state, values=("ALL", "RUNNING", "FAILED", "PENDING", "COMPLETED", "UNKNOWN"), state="readonly", width=13).pack(side="left", padx=6)
    def reset_page(*_):
        page_index[0] = 0
        refresh_table()
    search.trace_add("write", reset_page)
    state.trace_add("write", reset_page)
    summary = tk.StringVar(value="Aucune donnée chargée")
    overview = tk.StringVar(value="Supervision : aucune donnée chargée")
    ttk.Label(jobs, textvariable=summary, font=("Segoe UI", 11, "bold")).grid(row=2, column=0, sticky="w")
    ttk.Button(filters, text="Voir les échecs", command=lambda: (search.set(""), state.set("FAILED"))).pack(side="left", padx=6)
    ttk.Button(filters, text="Voir les états inconnus", command=lambda: (search.set(""), state.set("UNKNOWN"))).pack(side="left", padx=6)
    ttk.Button(filters, text="Tous les jobs", command=lambda: (search.set(""), state.set("ALL"))).pack(side="left")
    def export_summary():
        if not rows:
            messagebox.showinfo("Export de supervision", "Aucune donnée chargée à exporter.")
            return
        target = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")], title="Exporter la synthèse (sans identifiants de jobs)")
        if not target: return
        from odmm_supervision_export_v2288 import write_summary
        try:
            write_summary(rows, target)
            status.set("Synthèse anonymisée exportée — aucune donnée de job ni jeton")
        except (OSError, ValueError):
            messagebox.showerror("Export impossible", "Fichier existant, chemin inaccessible ou données invalides. Aucun fichier écrasé.")
    def load_demo():
        """Load in-memory synthetic examples, never contact server or mutate jobs."""
        from odmm_sample_report_v2289 import sample_rows
        generation[0] += 1  # invalidate outstanding network responses
        while not inbox.empty():
            try: inbox.get_nowait()
            except queue.Empty: break
        load_button.configure(state="normal")
        rows.clear()
        rows.extend(sample_rows())
        search.set("")
        state.set("ALL")
        refresh_table()
        overview.set("DÉMONSTRATION FICTIVE — " + " | ".join(overview_lines(supervision(rows))))
        status.set("DÉMONSTRATION FICTIVE — aucune connexion NAS / API ; aucune migration exécutée")
    ttk.Button(filters, text="Démo fictive", command=load_demo).pack(side="left", padx=6)
    ttk.Button(filters, text="Exporter synthèse", command=export_summary).pack(side="left", padx=6)
    ttk.Label(jobs, textvariable=overview, wraplength=1050, justify="left").grid(row=6, column=0, sticky="w", pady=(4, 0))
    table_frame = ttk.Frame(jobs)
    table_frame.grid(row=3, column=0, sticky="nsew", pady=8)
    table_frame.columnconfigure(0, weight=1)
    table_frame.rowconfigure(0, weight=1)
    tree = ttk.Treeview(table_frame, columns=("id", "status"), show="headings", selectmode="browse")
    # Status highlighting is presentation-only; server data remains untouched.
    for tag, foreground in (("FAILED", "#a61b1b"), ("RUNNING", "#145a9e"), ("COMPLETED", "#20663b"), ("PENDING", "#7a5900"), ("UNKNOWN", "#6b587a")):
        tree.tag_configure(tag, foreground=foreground)
    vertical = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    sort_state = {"column": "id", "reverse": False}
    def sort_table(column):
        reverse = not sort_state["reverse"] if sort_state["column"] == column else False
        sort_state.update(column=column, reverse=reverse)
        page_index[0] = 0
        refresh_table()
        tree.heading(column, text=("Migration / Job" if column == "id" else "État") + (" ▼" if reverse else " ▲"))
    for column in ("id", "status"):
        tree.heading(column, command=lambda c=column: sort_table(c))
    tree.heading("id", text="Migration / Job")
    tree.heading("status", text="État")
    tree.column("id", width=480)
    tree.column("status", width=180)
    tree.grid(row=0, column=0, sticky="nsew")
    pager = ttk.Frame(jobs)
    pager.grid(row=7, column=0, sticky="ew", pady=(0, 5))
    page_label = tk.StringVar(value="Page 1 / 1")
    previous_button = ttk.Button(pager, text="◀ Précédent", command=lambda: change_page(-1))
    previous_button.pack(side="left")
    ttk.Label(pager, textvariable=page_label).pack(side="left", padx=12)
    next_button = ttk.Button(pager, text="Suivant ▶", command=lambda: change_page(1))
    next_button.pack(side="left")
    def change_page(delta):
        page_index[0] += delta
        refresh_table()
    # Read-only, scrollable detail panel: long triage evidence remains accessible.
    detail_frame = ttk.LabelFrame(jobs, text="Détails de la migration (lecture seule)", padding=6)
    detail_frame.grid(row=4, column=0, sticky="ew", pady=(3, 3))
    detail_frame.columnconfigure(0, weight=1)
    detail_text = tk.Text(detail_frame, height=6, wrap="word", font=("Consolas", 10), state="disabled", takefocus=True)
    detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=detail_text.yview)
    detail_text.configure(yscrollcommand=detail_scroll.set)
    detail_text.grid(row=0, column=0, sticky="ew")
    detail_scroll.grid(row=0, column=1, sticky="ns")
    def render_detail(*_):
        detail_text.configure(state="normal")
        detail_text.delete("1.0", "end")
        detail_text.insert("1.0", detail.get())
        detail_text.configure(state="disabled")
    detail.trace_add("write", render_detail)
    render_detail()
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
    tree.bind("<Return>", select_job)
    tree.bind("<Double-1>", select_job)
    root.bind("<Control-r>", lambda _e: load() if str(load_button.cget("state")) != "disabled" else None)
    def focus_search(_event=None):
        tabs.select(jobs)
        search_entry.focus_set()
        search_entry.selection_range(0, "end")
        return "break"
    root.bind("<Control-f>", focus_search)
    root.bind("<F5>", lambda _e: load() if str(load_button.cget("state")) != "disabled" else None)
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
    ttk.Label(about, text="Raccourcis : F5 / Ctrl+R actualiser, Ctrl+F ouvrir la recherche, Échap effacer le filtre, Ctrl+Tab changer d’onglet.").pack(anchor="w", pady=(0, 12))
    ttk.Label(about, text="ODMM Compact Windows V" + VERSION + "\nAuteur : " + AUTHOR + "\n\nClient léger en lecture seule.\nAucune copie, modification ACL, bascule ou migration depuis ce programme.\nLes opérations réelles sont exécutées par le serveur ODMM.", justify="left", wraplength=650).pack(anchor="w")
    def drain():
        if closed[0]: return
        try:
            while True:
                rid, data, error = inbox.get_nowait()
                if rid != generation[0]: continue
                load_button.configure(state="normal")
                if error:
                    status.set("Échec de consultation : " + error + " | " + refresh_message("NETWORK", len(rows)))
                    detail.set("Données précédentes conservées ; vérifier la connexion et le jeton.")
                else:
                    if not isinstance(data, list) or len(data) > 100000 or any(not isinstance(r, dict) for r in data):
                        status.set(refresh_message("PAYLOAD", len(rows)))
                        detail.set("Données précédentes conservées ; aucune modification distante.")
                        continue
                    accepted, outcome = resolve_refresh(rows, rid, generation[0], data, None, validate_jobs)
                    if outcome != "OK":
                        status.set(refresh_message("VALIDATION", len(rows)))
                        detail.set("Données précédentes conservées ; contacter l’administrateur du serveur.")
                        continue
                    rows.clear()
                    rows.extend(accepted)
                    refresh_table()
                    overview.set(" | ".join(overview_lines(supervision(rows))))
                    status.set("Consultation terminée — lecture seule · " + server_limit_notice(len(rows)))
        except queue.Empty: pass
        root.after(80, drain)
    def close():
        closed[0] = True
        generation[0] += 1
        token.set("")
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    def clear_search(_event=None):
        if tabs.select() == str(jobs) and search.get():
            search.set("")
            search_entry.focus_set()
            return "break"
    root.bind("<Escape>", clear_search)
    root.after(80, drain)
    import os
    if os.environ.get("ODMM_SCREENSHOT_DEMO") == "1":
        root.after(300, load_demo)
        root.after(6500, root.destroy)
    root.mainloop()

if __name__ == "__main__": main()
