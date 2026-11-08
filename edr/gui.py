"""
Exploidus EDR GUI — Full dashboard built with customtkinter.

Install dependency (once):
    pip install customtkinter

Run:
    python -m edr.gui
    or
    exploidus-edr-gui          (if entry point is registered)
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk

from edr.config import Config, DEFAULT_CONFIG_PATH
from edr.engine.scanner import Scanner, ScanResult, ThreatLevel
from edr.engine.monitor import RealtimeMonitor
from edr.engine.behavior import BehaviorMonitor, scan_all_processes
from edr.engine.updater import SignatureUpdater
from edr.quarantine.vault import QuarantineVault
from edr.reports.logger import ScanLogger


# Theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_BG        = "#0f1117"
_SIDEBAR   = "#161b27"
_CARD      = "#1e2435"
_ACCENT    = "#4f8ef7"
_ACCENT2   = "#e94560"
_GREEN     = "#2ecc71"
_YELLOW    = "#f39c12"
_TEXT      = "#e0e0e0"
_SUBTEXT   = "#8a8fa8"
_FONT      = ("Segoe UI", 12)
_FONT_B    = ("Segoe UI", 12, "bold")
_FONT_SM   = ("Segoe UI", 10)
_FONT_LG   = ("Segoe UI", 14, "bold")
_FONT_XL   = ("Segoe UI", 22, "bold")


def _severity_color(level: str) -> str:
    if level == "malicious":
        return _ACCENT2
    if level == "suspicious":
        return _YELLOW
    return _GREEN



# Reusable widgets


class SectionTitle(ctk.CTkLabel):
    def __init__(self, parent, text, **kw):
        super().__init__(parent, text=text, font=_FONT_LG,
                         text_color=_TEXT, **kw)


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, title: str, value: str, color: str = _ACCENT):
        super().__init__(parent, fg_color=_CARD, corner_radius=12)
        ctk.CTkLabel(self, text=title, font=_FONT_SM,
                     text_color=_SUBTEXT).pack(anchor="w", padx=16, pady=(14, 2))
        self._val = ctk.CTkLabel(self, text=value, font=_FONT_XL,
                                  text_color=color)
        self._val.pack(anchor="w", padx=16, pady=(0, 14))

    def set(self, value: str):
        self._val.configure(text=value)


class LogBox(ctk.CTkTextbox):
    """Scrolling log box with append helper."""
    def __init__(self, parent, **kw):
        super().__init__(parent, state="disabled", font=_FONT_SM,
                         fg_color=_BG, text_color=_TEXT, **kw)

    def append(self, msg: str):
        self.configure(state="normal")
        self.insert("end", msg + "\n")
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")



# Simple Treeview wrapper (uses ttk since CTk has no table widget)

class SimpleTable(tk.Frame):
    def __init__(self, parent, columns: list[tuple[str, int]], **kw):
        super().__init__(parent, bg=_CARD, **kw)
        import tkinter.ttk as ttk

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("PyS.Treeview",
                         background=_CARD, foreground=_TEXT,
                         fieldbackground=_CARD, rowheight=28,
                         borderwidth=0, font=_FONT_SM)
        style.configure("PyS.Treeview.Heading",
                         background="#1a2035", foreground=_SUBTEXT,
                         relief="flat", font=_FONT_SM)
        style.map("PyS.Treeview", background=[("selected", "#2a3555")])

        col_ids = [c[0] for c in columns]
        self._tree = ttk.Treeview(self, columns=col_ids, show="headings",
                                   style="PyS.Treeview")
        for cid, width in columns:
            self._tree.heading(cid, text=cid)
            self._tree.column(cid, width=width, minwidth=60)

        vsb = ttk.Scrollbar(self, orient="vertical",
                             command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def insert(self, values: tuple, tag: str = ""):
        self._tree.insert("", "end", values=values, tags=(tag,) if tag else ())
        if tag:
            self._tree.tag_configure(tag, foreground=_severity_color(tag))
        self._tree.yview_moveto(1)

    def clear(self):
        self._tree.delete(*self._tree.get_children())

    def selected_values(self) -> Optional[tuple]:
        sel = self._tree.selection()
        if sel:
            return self._tree.item(sel[0], "values")
        return None

    def all_rows(self) -> list:
        return [self._tree.item(r, "values")
                for r in self._tree.get_children()]



# Main application


class ExploidusEDRApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Exploidus EDR - Endpoint Detection & Response")
        self.geometry("1150x720")
        self.minsize(900, 600)
        self.configure(fg_color=_BG)

        self._cfg     = Config.load(DEFAULT_CONFIG_PATH)
        self._scanner: Optional[Scanner]       = None
        self._monitor: Optional[RealtimeMonitor] = None
        self._bhv_mon: Optional[BehaviorMonitor]  = None
        self._scan_thread: Optional[threading.Thread] = None
        self._log_q: queue.Queue = queue.Queue()

        self._build_layout()
        self._refresh_scanner()
        self._show("dashboard")
        self.after(300, self._process_log_queue)

    
    # Layout
    # 

    def _build_layout(self):
        # Sidebar
        self._sidebar = ctk.CTkFrame(self, width=210, fg_color=_SIDEBAR,
                                      corner_radius=0)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        ctk.CTkLabel(self._sidebar, text="Exploidus EDR",
                     font=("Segoe UI", 17, "bold"),
                     text_color=_ACCENT).pack(pady=(28, 6), padx=18, anchor="w")
        ctk.CTkLabel(self._sidebar, text="v1.0.0 • Endpoint Detection & Response",
                     font=_FONT_SM, text_color=_SUBTEXT).pack(
                         padx=18, anchor="w", pady=(0, 24))

        self._nav_btns: dict[str, ctk.CTkButton] = {}
        pages = [
            ("dashboard",  "Dashboard"),
            ("scan",       "Scan"),
            ("monitor",    "Real-time Monitor"),
            ("quarantine", "Quarantine Vault"),
            ("threats",    "Threat Telemetry"),
            ("update",     "Update Signatures"),
            ("behavior",   "Process Behavior"),
            ("settings",   "Configuration"),
        ]
        for key, label in pages:
            btn = ctk.CTkButton(
                self._sidebar, text=label, anchor="w",
                fg_color="transparent", text_color=_TEXT,
                hover_color="#252d44", font=_FONT,
                corner_radius=8, height=38,
                command=lambda k=key: self._show(k),
            )
            btn.pack(fill="x", padx=10, pady=2)
            self._nav_btns[key] = btn

        # Content area
        self._content = ctk.CTkFrame(self, fg_color=_BG, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        # Status bar
        self._status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(self, textvariable=self._status_var,
                     font=_FONT_SM, text_color=_SUBTEXT,
                     fg_color=_SIDEBAR).pack(
                         side="bottom", fill="x", ipady=4)

        # Build all frames
        self._frames: dict[str, ctk.CTkFrame] = {}
        builders = {
            "dashboard":  self._build_dashboard,
            "scan":       self._build_scan,
            "monitor":    self._build_monitor,
            "quarantine": self._build_quarantine,
            "threats":    self._build_threats,
            "update":     self._build_update,
            "behavior":   self._build_behavior,
            "settings":   self._build_settings,
        }
        for name, builder in builders.items():
            frame = ctk.CTkFrame(self._content, fg_color=_BG, corner_radius=0)
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self._frames[name] = frame
            builder(frame)

    def _show(self, name: str):
        for key, btn in self._nav_btns.items():
            btn.configure(fg_color=_ACCENT if key == name else "transparent",
                          text_color="white" if key == name else _TEXT)
        self._frames[name].lift()
        if name == "dashboard":
            self._refresh_dashboard()
        elif name == "quarantine":
            self._refresh_quarantine()
        elif name == "threats":
            self._refresh_threats()

    
    # Dashboard
    

    def _build_dashboard(self, f: ctk.CTkFrame):
        pad = {"padx": 28, "pady": (20, 6)}
        SectionTitle(f, "Dashboard").pack(anchor="w", **pad)

        card_row = ctk.CTkFrame(f, fg_color="transparent")
        card_row.pack(fill="x", padx=28, pady=(6, 18))

        self._dc_scanned   = StatCard(card_row, "Files Scanned",   "0", _ACCENT)
        self._dc_threats   = StatCard(card_row, "Threats Found",    "0", _ACCENT2)
        self._dc_quarant   = StatCard(card_row, "In Quarantine",    "0", _YELLOW)
        self._dc_sigs      = StatCard(card_row, "Signatures",       "0", _GREEN)

        for c in (self._dc_scanned, self._dc_threats,
                  self._dc_quarant, self._dc_sigs):
            c.pack(side="left", expand=True, fill="both", padx=6)

        SectionTitle(f, "Recent Threats").pack(anchor="w", padx=28, pady=(4, 6))
        self._db_table = SimpleTable(f, [
            ("File", 280), ("Level", 100), ("Threat", 260), ("Scanned At", 150),
        ])
        self._db_table.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def _refresh_dashboard(self):
        log   = ScanLogger(Path(self._cfg.log_dir))
        vault = QuarantineVault(Path(self._cfg.quarantine_dir))
        all_r = log.get_all(2000)
        thrs  = [r for r in all_r if r.get("threat_level") != "clean"]

        self._dc_scanned.set(str(len(all_r)))
        self._dc_threats.set(str(len(thrs)))
        self._dc_quarant.set(str(vault.count))
        self._dc_sigs.set(f"{self._scanner.signature_count:,}"
                          if self._scanner else "0")

        self._db_table.clear()
        for t in thrs[-20:]:
            lvl = t.get("threat_level", "")
            self._db_table.insert((
                Path(t["path"]).name,
                lvl.upper(),
                t.get("threat_name") or "",
                time.strftime("%m-%d %H:%M", time.localtime(t["scanned_at"])),
            ), tag=lvl)

    
    # Scan
    

    def _build_scan(self, f: ctk.CTkFrame):
        SectionTitle(f, "Scan Files / Folders").pack(
            anchor="w", padx=28, pady=(20, 10))

        row = ctk.CTkFrame(f, fg_color="transparent")
        row.pack(fill="x", padx=28, pady=(0, 8))
        self._scan_path = ctk.CTkEntry(row, placeholder_text="Select path to scan…",
                                        font=_FONT, height=38, fg_color=_CARD,
                                        border_color="#2a3555")
        self._scan_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(row, text="Browse", width=90, height=38,
                      fg_color=_ACCENT, font=_FONT_B,
                      command=self._browse_scan).pack(side="left")

        opts = ctk.CTkFrame(f, fg_color="transparent")
        opts.pack(fill="x", padx=28, pady=(0, 10))
        self._opt_recursive = ctk.CTkCheckBox(opts, text="Recursive",
                                               font=_FONT, text_color=_TEXT)
        self._opt_recursive.select()
        self._opt_recursive.pack(side="left", padx=(0, 20))
        self._opt_quarantine = ctk.CTkCheckBox(opts, text="Auto-quarantine threats",
                                                font=_FONT, text_color=_TEXT)
        self._opt_quarantine.pack(side="left")

        self._scan_btn = ctk.CTkButton(
            f, text="▶  Start Scan", height=42, font=_FONT_LG,
            fg_color=_ACCENT, hover_color="#3a7de8",
            command=self._start_scan)
        self._scan_btn.pack(padx=28, pady=(0, 10), anchor="w")

        self._scan_progress = ctk.CTkProgressBar(f, height=6, fg_color=_CARD,
                                                   progress_color=_ACCENT)
        self._scan_progress.set(0)
        self._scan_progress.pack(fill="x", padx=28, pady=(0, 6))

        self._scan_status = ctk.CTkLabel(f, text="", font=_FONT_SM,
                                          text_color=_SUBTEXT)
        self._scan_status.pack(anchor="w", padx=28, pady=(0, 6))

        self._scan_table = SimpleTable(f, [
            ("File", 300), ("Status", 100), ("Threat", 240), ("ms", 60),
        ])
        self._scan_table.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def _browse_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan") or \
               filedialog.askopenfilename(title="Select file to scan")
        if path:
            self._scan_path.delete(0, "end")
            self._scan_path.insert(0, path)

    def _start_scan(self):
        raw = self._scan_path.get().strip()
        if not raw:
            messagebox.showwarning("No path", "Please enter a path to scan.")
            return
        target = Path(raw)
        if not target.exists():
            messagebox.showerror("Not found", f"Path does not exist:\n{target}")
            return

        self._scan_table.clear()
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._scan_progress.set(0)
        self._scan_status.configure(text="Initializing…")
        self._status_var.set("Scanning…")

        recursive  = self._opt_recursive.get()
        do_quarant = self._opt_quarantine.get()

        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, recursive, do_quarant),
            daemon=True,
        )
        self._scan_thread.start()

    def _scan_worker(self, target: Path, recursive: bool, do_quarant: bool):
        vault   = QuarantineVault(Path(self._cfg.quarantine_dir)) if do_quarant else None
        scanner = self._scanner
        total   = threats = 0

        paths = ([target] if target.is_file()
                 else list(target.rglob("*") if recursive else target.glob("*")))
        file_paths = [p for p in paths if p.is_file()]
        n = len(file_paths) or 1

        for i, fp in enumerate(file_paths):
            result = scanner.scan_file(fp)
            total += 1
            progress = (i + 1) / n

            if result.is_threat:
                threats += 1
                tag  = result.threat_level.value
                name = Path(result.path).name
                self._log_q.put(("scan_row", (
                    name,
                    result.threat_level.value.upper(),
                    result.threat_name or "",
                    f"{result.scan_duration_ms:.0f}",
                    tag,
                )))
                if do_quarant and vault and result.threat_level == ThreatLevel.MALICIOUS:
                    try:
                        vault.quarantine(Path(result.path),
                                         result.threat_name,
                                         result.md5, result.sha256)
                    except Exception:
                        pass

            self._log_q.put(("scan_progress", (
                progress,
                f"Scanned {total}/{len(file_paths)} — {threats} threat(s) found",
            )))

        self._log_q.put(("scan_done", (total, threats)))

    
    # Monitor


    def _build_monitor(self, f: ctk.CTkFrame):
        SectionTitle(f, "Real-time Monitor").pack(
            anchor="w", padx=28, pady=(20, 10))

        path_row = ctk.CTkFrame(f, fg_color="transparent")
        path_row.pack(fill="x", padx=28, pady=(0, 8))
        self._mon_path = ctk.CTkEntry(path_row,
                                       placeholder_text="Add folder to watch…",
                                       font=_FONT, height=36, fg_color=_CARD,
                                       border_color="#2a3555")
        self._mon_path.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(path_row, text="Browse", width=90, height=36,
                      fg_color="#2a3555", font=_FONT,
                      command=lambda: self._mon_path.insert(
                          0, filedialog.askdirectory() or "")
                      ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(path_row, text="Add", width=70, height=36,
                      fg_color=_ACCENT, font=_FONT,
                      command=self._add_watch_path).pack(side="left")

        self._watch_list = ctk.CTkTextbox(f, height=90, font=_FONT_SM,
                                           fg_color=_CARD, text_color=_TEXT)
        self._watch_list.pack(fill="x", padx=28, pady=(0, 10))
        self._watch_list.configure(state="disabled")

        btn_row = ctk.CTkFrame(f, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 12))
        self._mon_btn = ctk.CTkButton(btn_row, text="Start Monitor",
                                       height=40, font=_FONT_LG,
                                       fg_color=_GREEN, hover_color="#27ae60",
                                       command=self._toggle_monitor)
        self._mon_btn.pack(side="left", padx=(0, 10))
        self._bhv_chk = ctk.CTkCheckBox(btn_row, text="+ Behavior monitor",
                                          font=_FONT, text_color=_TEXT)
        self._bhv_chk.pack(side="left")

        SectionTitle(f, "Live Events").pack(anchor="w", padx=28, pady=(4, 4))
        self._mon_log = LogBox(f)
        self._mon_log.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        self._watch_paths: list[str] = []

    def _add_watch_path(self):
        p = self._mon_path.get().strip()
        if p and p not in self._watch_paths:
            self._watch_paths.append(p)
            self._watch_list.configure(state="normal")
            self._watch_list.insert("end", p + "\n")
            self._watch_list.configure(state="disabled")
        self._mon_path.delete(0, "end")

    def _toggle_monitor(self):
        if self._monitor and self._monitor.is_running:
            self._monitor.stop()
            if self._bhv_mon:
                self._bhv_mon.stop()
                self._bhv_mon = None
            self._monitor = None
            self._mon_btn.configure(text="Start Monitor", fg_color=_GREEN)
            self._mon_log.append("[Monitor] Stopped.")
            self._status_var.set("Monitor stopped")
            return

        paths = self._watch_paths or self._cfg.monitor_paths
        if not paths:
            messagebox.showwarning("No paths", "Add at least one folder to watch.")
            return

        def on_threat(result: ScanResult):
            msg = (f"[THREAT] {result.threat_level.value.upper()} | "
                   f"{result.threat_name} | {Path(result.path).name}")
            self._log_q.put(("mon_log", msg))

        def on_scan(result: ScanResult):
            self._log_q.put(("mon_log",
                              f"[Scan] {Path(result.path).name} — {result.threat_level.value}"))

        self._monitor = RealtimeMonitor(self._scanner, self._cfg,
                                         on_threat=on_threat, on_scan=on_scan)
        self._monitor.start(paths)

        if self._bhv_chk.get():
            def on_bhv(alert):
                self._log_q.put(("mon_log",
                                  f"[BEHAVIOR] PID {alert.pid} | {alert.process_name} | "
                                  f"score={alert.score}"))
            self._bhv_mon = BehaviorMonitor(on_alert=on_bhv,
                                             scan_interval=self._cfg.behavior_scan_interval)
            self._bhv_mon.start()

        self._mon_btn.configure(text="Stop Monitor", fg_color=_ACCENT2)
        self._mon_log.append(f"[Monitor] Started — watching {len(paths)} path(s)")
        self._status_var.set(f"Monitoring {len(paths)} path(s)…")

    
    # Quarantine
    
    def _build_quarantine(self, f: ctk.CTkFrame):
        SectionTitle(f, "Quarantine Vault").pack(
            anchor="w", padx=28, pady=(20, 10))

        self._q_table = SimpleTable(f, [
            ("ID",           80),
            ("Original Path", 340),
            ("Threat",       200),
            ("Date",         130),
        ])
        self._q_table.pack(fill="both", expand=True, padx=28, pady=(0, 12))

        btn_row = ctk.CTkFrame(f, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 20))
        ctk.CTkButton(btn_row, text="Restore File", height=38, width=130,
                      fg_color=_GREEN, font=_FONT_B,
                      command=self._restore_selected).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="Delete File", height=38, width=130,
                      fg_color=_ACCENT2, font=_FONT_B,
                      command=self._delete_selected).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_row, text="Delete All", height=38, width=110,
                      fg_color="#3a2020", font=_FONT,
                      command=self._delete_all_quarantine).pack(side="left")

    def _refresh_quarantine(self):
        vault = QuarantineVault(Path(self._cfg.quarantine_dir))
        self._q_table.clear()
        for e in vault.list_entries():
            self._q_table.insert((
                e.id[:8],
                e.original_path,
                e.threat_name or "Unknown",
                time.strftime("%Y-%m-%d %H:%M", time.localtime(e.quarantined_at)),
            ))

    def _restore_selected(self):
        row = self._q_table.selected_values()
        if not row:
            messagebox.showinfo("Select row", "Click a row first.")
            return
        vault = QuarantineVault(Path(self._cfg.quarantine_dir))
        try:
            vault.restore(row[0])
            self._refresh_quarantine()
            messagebox.showinfo("Restored", f"File restored to original location.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _delete_selected(self):
        row = self._q_table.selected_values()
        if not row:
            messagebox.showinfo("Select row", "Click a row first.")
            return
        if not messagebox.askyesno("Confirm", "Permanently delete this file?"):
            return
        vault = QuarantineVault(Path(self._cfg.quarantine_dir))
        try:
            vault.delete(row[0])
            self._refresh_quarantine()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _delete_all_quarantine(self):
        if not messagebox.askyesno("Confirm", "Permanently delete ALL quarantined files?"):
            return
        vault = QuarantineVault(Path(self._cfg.quarantine_dir))
        for e in vault.list_entries():
            try:
                vault.delete(e.id)
            except Exception:
                pass
        self._refresh_quarantine()

    
    # Threats
    

    def _build_threats(self, f: ctk.CTkFrame):
        SectionTitle(f, "Threat Report").pack(
            anchor="w", padx=28, pady=(20, 10))

        bar = ctk.CTkFrame(f, fg_color="transparent")
        bar.pack(fill="x", padx=28, pady=(0, 8))
        ctk.CTkButton(bar, text="↻  Refresh", width=100, height=34,
                      fg_color=_ACCENT, font=_FONT,
                      command=self._refresh_threats).pack(side="left", padx=(0, 10))
        ctk.CTkButton(bar, text="Clear Log", width=100, height=34,
                      fg_color="#2a2a2a", font=_FONT,
                      command=self._clear_threat_log).pack(side="left")

        self._thr_table = SimpleTable(f, [
            ("File",       280),
            ("Level",       90),
            ("Threat",     240),
            ("MD5",        200),
            ("Scanned At", 130),
        ])
        self._thr_table.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def _refresh_threats(self):
        log = ScanLogger(Path(self._cfg.log_dir))
        self._thr_table.clear()
        for t in log.get_threats(200):
            lvl = t.get("threat_level", "")
            self._thr_table.insert((
                Path(t["path"]).name,
                lvl.upper(),
                t.get("threat_name") or "",
                t.get("md5", "")[:16] + "…",
                time.strftime("%m-%d %H:%M", time.localtime(t["scanned_at"])),
            ), tag=lvl)

    def _clear_threat_log(self):
        if messagebox.askyesno("Clear", "Clear all scan logs?"):
            ScanLogger(Path(self._cfg.log_dir)).clear()
            self._thr_table.clear()

    
    # Update
    

    def _build_update(self, f: ctk.CTkFrame):
        SectionTitle(f, "Update Signatures").pack(
            anchor="w", padx=28, pady=(20, 10))

        info = ctk.CTkFrame(f, fg_color=_CARD, corner_radius=12)
        info.pack(fill="x", padx=28, pady=(0, 16))

        self._upd_sig_lbl = ctk.CTkLabel(
            info, text="Current signatures: checking…",
            font=_FONT, text_color=_TEXT)
        self._upd_sig_lbl.pack(anchor="w", padx=20, pady=(14, 2))
        self._upd_src_lbl = ctk.CTkLabel(
            info,
            text="Sources: MalwareBazaar (free) + ClamAV CDN (free)",
            font=_FONT_SM, text_color=_SUBTEXT)
        self._upd_src_lbl.pack(anchor="w", padx=20, pady=(0, 14))

        btn_row = ctk.CTkFrame(f, fg_color="transparent")
        btn_row.pack(fill="x", padx=28, pady=(0, 12))
        self._upd_btn = ctk.CTkButton(
            btn_row, text="⬇  Update Now", height=42, font=_FONT_LG,
            fg_color=_ACCENT, hover_color="#3a7de8",
            command=self._start_update)
        self._upd_btn.pack(side="left", padx=(0, 12))
        self._upd_force_chk = ctk.CTkCheckBox(
            btn_row, text="Force re-download", font=_FONT, text_color=_TEXT)
        self._upd_force_chk.pack(side="left")

        SectionTitle(f, "Update Log").pack(anchor="w", padx=28, pady=(4, 4))
        self._upd_log = LogBox(f)
        self._upd_log.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        self.after(500, self._refresh_sig_count)

    def _refresh_sig_count(self):
        if self._scanner:
            self._upd_sig_lbl.configure(
                text=f"Current signatures: {self._scanner.signature_count:,}")

    def _start_update(self):
        self._upd_btn.configure(state="disabled", text="Updating…")
        self._upd_log.clear()
        force = bool(self._upd_force_chk.get())

        def worker():
            def log(msg):
                self._log_q.put(("upd_log", msg))

            updater = SignatureUpdater(
                cache_dir   = Path(self._cfg.clamav_cache_dir),
                sig_db_path = Path(self._cfg.signature_db),
                on_log      = log,
            )
            updater.run(force=force)
            self._log_q.put(("upd_done", None))

        threading.Thread(target=worker, daemon=True).start()

    
    # Behavior scan
    

    def _build_behavior(self, f: ctk.CTkFrame):
        SectionTitle(f, "Behavior Scan (Running Processes)").pack(
            anchor="w", padx=28, pady=(20, 10))

        ctk.CTkButton(f, text="Scan Active Processes", height=42,
                      font=_FONT_LG, fg_color=_ACCENT,
                      command=self._run_behavior_scan).pack(
                          padx=28, pady=(0, 12), anchor="w")

        self._bhv_table = SimpleTable(f, [
            ("PID",     70),
            ("Process", 200),
            ("Verdict", 100),
            ("Score",    70),
            ("Top Flag", 400),
        ])
        self._bhv_table.pack(fill="both", expand=True, padx=28, pady=(0, 20))

    def _run_behavior_scan(self):
        self._bhv_table.clear()
        self._status_var.set("Scanning processes…")

        def worker():
            alerts = scan_all_processes()
            self._log_q.put(("bhv_results", alerts))

        threading.Thread(target=worker, daemon=True).start()

    
    # Settings
    

    def _build_settings(self, f: ctk.CTkFrame):
        SectionTitle(f, "Settings").pack(
            anchor="w", padx=28, pady=(20, 10))

        scroll = ctk.CTkScrollableFrame(f, fg_color=_BG)
        scroll.pack(fill="both", expand=True, padx=28, pady=(0, 20))

        fields = [
            ("Max File Size (MB)",  "max_file_size_mb",      "256"),
            ("Heuristic Threshold", "heuristic_threshold",   "60"),
            ("Excluded Extensions", "excluded_extensions",   ".log,.tmp,.bak"),
        ]
        self._cfg_vars: dict[str, ctk.CTkEntry] = {}

        for label, key, default in fields:
            ctk.CTkLabel(scroll, text=label, font=_FONT_B,
                          text_color=_TEXT).pack(anchor="w", pady=(10, 2))
            val = getattr(self._cfg, key, default)
            if isinstance(val, list):
                val = ",".join(val)
            entry = ctk.CTkEntry(scroll, font=_FONT, height=36,
                                  fg_color=_CARD, border_color="#2a3555")
            entry.insert(0, str(val))
            entry.pack(fill="x", pady=(0, 4))
            self._cfg_vars[key] = entry

        self._auto_q_var = ctk.CTkCheckBox(scroll, text="Auto-quarantine threats",
                                            font=_FONT, text_color=_TEXT)
        if self._cfg.auto_quarantine:
            self._auto_q_var.select()
        self._auto_q_var.pack(anchor="w", pady=(14, 4))

        self._bhv_var = ctk.CTkCheckBox(scroll, text="Enable behavior monitor on startup",
                                         font=_FONT, text_color=_TEXT)
        if self._cfg.behavior_monitor_enabled:
            self._bhv_var.select()
        self._bhv_var.pack(anchor="w", pady=(4, 14))

        ctk.CTkButton(scroll, text="Save Configuration", height=40,
                      fg_color=_ACCENT, font=_FONT_LG,
                      command=self._save_settings).pack(anchor="w", pady=(4, 0))

    def _save_settings(self):
        try:
            self._cfg.max_file_size_mb    = int(self._cfg_vars["max_file_size_mb"].get())
            self._cfg.heuristic_threshold = int(self._cfg_vars["heuristic_threshold"].get())
            raw_ext = self._cfg_vars["excluded_extensions"].get()
            self._cfg.excluded_extensions = [e.strip() for e in raw_ext.split(",")]
            self._cfg.auto_quarantine     = bool(self._auto_q_var.get())
            self._cfg.behavior_monitor_enabled = bool(self._bhv_var.get())
            self._cfg.save(DEFAULT_CONFIG_PATH)
            self._refresh_scanner()
            messagebox.showinfo("Saved", "Settings saved.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    
    # Helpers
    

    def _refresh_scanner(self):
        self._scanner = Scanner(self._cfg)
        self._status_var.set(
            f"Ready  •  {self._scanner.signature_count:,} signatures loaded")

    def _process_log_queue(self):
        try:
            while True:
                kind, data = self._log_q.get_nowait()

                if kind == "scan_row":
                    *vals, tag = data
                    self._scan_table.insert(tuple(vals), tag=tag)

                elif kind == "scan_progress":
                    progress, msg = data
                    self._scan_progress.set(progress)
                    self._scan_status.configure(text=msg)
                    self._status_var.set(msg)

                elif kind == "scan_done":
                    total, threats = data
                    self._scan_btn.configure(state="normal", text="▶  Start Scan")
                    self._scan_progress.set(1)
                    msg = f"Done — {total} files scanned, {threats} threat(s) found"
                    self._scan_status.configure(text=msg)
                    self._status_var.set(msg)

                elif kind == "mon_log":
                    self._mon_log.append(data)

                elif kind == "upd_log":
                    self._upd_log.append(data)

                elif kind == "upd_done":
                    self._upd_btn.configure(state="normal", text="⬇  Update Now")
                    self._refresh_scanner()
                    self._refresh_sig_count()

                elif kind == "bhv_results":
                    alerts = data
                    self._bhv_table.clear()
                    for a in sorted(alerts, key=lambda x: x.score, reverse=True):
                        tag = a.verdict
                        self._bhv_table.insert((
                            str(a.pid),
                            a.process_name,
                            a.verdict.upper(),
                            str(a.score),
                            a.flags[0] if a.flags else "",
                        ), tag=tag)
                    self._status_var.set(
                        f"Behavior scan done — {len(alerts)} suspicious process(es)")

        except queue.Empty:
            pass
        finally:
            self.after(150, self._process_log_queue)

    def on_close(self):
        if self._monitor:
            self._monitor.stop()
        if self._bhv_mon:
            self._bhv_mon.stop()
        self.destroy()



# Entry point


def main():
    app = ExploidusEDRApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()