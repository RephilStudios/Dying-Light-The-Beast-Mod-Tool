# file: DLTB_All_in_One_v4.py
"""
DLTB All in One — Tkinter Single-File Script Editor & Packer

Matches the classic 3-column UI:
- Left: 'Load Game Data (.pak)' + folder tree.
- Center: live preview of the selected file; double-click a line to add/edit.
- Right: (1) search inputs, (2) results, (3) active edits with enable/disable checkboxes; pack button.

Notes
- Treats .pak as a ZIP container.
- No external deps; optional CLI '7z' NOT required here.
- v2: Adds functionality to find and delete entire blocks (e.g., AttackPreset).
- v3: Allows deleting blocks by double-clicking their header in the preview pane.
- v4: Adds "Edit" context menu option for active edits and prompts to save on close.
"""

from __future__ import annotations

import os
import re
import sys
import json
import shutil
import zipfile
import tempfile
import threading
import concurrent.futures
from functools import partial
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Literal
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

APP_NAME = "Dying Light The Beast Mod Tool"
APP_DIR = Path.home() / ".dltb_all_in_one"
CONFIG_PATH = APP_DIR / "config.json"

# Regexes for simple, robust matching in .scr files.
PARAM_RE = re.compile(r'Param\("([^"]+)",\s*(".*?"|\S+)\)\s*;')
PROP_RE  = re.compile(r'^\s*(\w+)\s*\((.*)\)\s*;')
ASSORT_RE = re.compile(r'Assortment\("([^"]+)"')
HEADER_RE = re.compile(r'(Item|Set)\s*\(\s*"([^"]+)"', re.I)
BLOCK_HEADER_RE = re.compile(r'^\s*(AttackPreset)\s*\(\s*"([^"]+)"\s*\)')


# ------------------------------ Model ----------------------------------------- #

class ModEdit:
    """A single change, which can be a line value replacement or a block deletion."""
    def __init__(
        self,
        file_path: str,
        line_number: int,
        original_value: str,
        current_value: str,
        description: str,
        param_name: str,
        is_enabled: bool = True,
        edit_type: Literal['VALUE_REPLACE', 'BLOCK_DELETE'] = 'VALUE_REPLACE',
        end_line_number: int = -1,
    ) -> None:
        self.file_path = file_path
        self.line_number = line_number
        self.original_value = original_value
        self.current_value = current_value
        self.description = description
        self.param_name = param_name
        self.is_enabled = is_enabled
        self.edit_type = edit_type
        self.end_line_number = end_line_number if end_line_number != -1 else line_number

    def key(self) -> Tuple[str, int]:
        return (self.file_path, self.line_number)


# ------------------------------ Settings -------------------------------------- #

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def read_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default

def write_json(p: Path, data) -> None:
    ensure_dir(p.parent)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)

class Settings:
    def __init__(self) -> None:
        data = read_json(CONFIG_PATH, {})
        self.last_pak_dir: str = data.get("last_pak_dir", str(Path.home()))
        self.dark_mode: bool = bool(data.get("dark_mode", False))

    def save(self) -> None:
        write_json(CONFIG_PATH, {
            "last_pak_dir": self.last_pak_dir,
            "dark_mode": self.dark_mode,
        })


# ------------------------------ Core scanning --------------------------------- #

def find_block_bounds(lines: List[str], start_ln: int) -> int:
    """Finds the end line of a block starting at start_ln by counting braces."""
    brace_depth = 0
    has_opened = False
    for i in range(start_ln, len(lines)):
        line_content = lines[i]
        if '{' in line_content:
            has_opened = True
        brace_depth += line_content.count('{') - line_content.count('}')
        if has_opened and brace_depth <= 0:
            return i
    return -1 # Not found

def scan_scr_for_hits(file_path: Path, kws: List[str]) -> List[ModEdit]:
    """Find Param/Property/Block matches in one .scr file, yielding ModEdit placeholders."""
    hits: List[ModEdit] = []
    if not kws:
        return hits
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return hits

    current_assort = None
    active_header = None
    header_name = None
    header_brace_depth = 0
    
    ln = 0
    while ln < len(lines):
        line = lines[ln]

        m_block = BLOCK_HEADER_RE.search(line)
        if m_block:
            block_type, block_name = m_block.groups()
            search_context = f"{block_type.lower()} {block_name.lower()}"
            if all(kw in search_context for kw in kws):
                start_ln = ln
                end_ln = find_block_bounds(lines, start_ln)
                
                if end_ln != -1:
                    hits.append(ModEdit(
                        file_path=str(file_path),
                        line_number=start_ln,
                        end_line_number=end_ln,
                        original_value=f'Block("{block_name}")',
                        current_value="<DELETED>",
                        description=f'{block_type}: "{block_name}"',
                        param_name=block_type,
                        edit_type='BLOCK_DELETE'
                    ))
                    ln = end_ln + 1
                    continue

        m_assort = ASSORT_RE.search(line)
        if m_assort:
            current_assort = m_assort.group(1)

        was_in_header = bool(active_header)
        if was_in_header:
            header_brace_depth += line.count("{") - line.count("}")
            if header_brace_depth <= 0:
                active_header = None
                header_name = None
        
        is_new_header = False
        if not was_in_header:
            if "Item(" in line or "Set(" in line:
                header_buf = line
                for look in range(1, 4):
                    if ln + look < len(lines):
                        nxt = lines[ln + look]
                        header_buf += " " + nxt
                        if "{" in nxt: break
                mh = HEADER_RE.search(header_buf)
                if mh:
                    header_name = mh.group(2)
                    active_header = header_buf
                    is_new_header = True
                    bline = header_buf.split("{", 1)[-1]
                    header_brace_depth = bline.count("{") - bline.count("}")

        m_param = PARAM_RE.search(line)
        if m_param:
            pname, val = m_param.groups()
            if all(kw in pname.lower() for kw in kws):
                hits.append(ModEdit(str(file_path), ln, val, val, pname, pname))

        pm = PROP_RE.search(line)
        if pm:
            pname, oval = pm.groups()
            oval = oval.strip()
            if active_header or is_new_header:
                search_context = (header_name or "").lower() + " " + pname.lower()
                if all(kw in search_context for kw in kws):
                    descr = header_name or current_assort or "Context"
                    hits.append(ModEdit(str(file_path), ln, oval, oval, descr, pname))
            else:
                search_context = pname.lower() + " " + oval.lower()
                if all(kw in search_context for kw in kws):
                    descr = Path(file_path).stem
                    hits.append(ModEdit(str(file_path), ln, oval, oval, descr, pname))
        
        ln += 1

    return hits


# ------------------------------ GUI ------------------------------------------- #

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1400x820")
        self.minsize(1200, 700)

        self.settings = Settings()
        ensure_dir(APP_DIR)

        self.temp_root: Optional[Path] = None
        self.current_file: Optional[Path] = None
        self.search_results: List[ModEdit] = []
        self.active_edits: Dict[Tuple[str, int], ModEdit] = {}
        self.path_to_id: Dict[Path, str] = {}
        self.progress_win: Optional[tk.Toplevel] = None
        self.spinner_angle = 0
        self.spinner_job = None
        self._search_after_id = None

        self._build_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        if self.settings.dark_mode:
            bg = "#1f2125"; fg = "#e7e7e7"
            self.configure(bg=bg)
            for cls in ["TFrame","TLabel","TButton","TEntry","Treeview","TNotebook","TLabelframe","TLabelframe.Label", "Listbox"]:
                style.configure(cls, background=bg, foreground=fg, fieldbackground=bg)
            style.map("Treeview", background=[("selected","#3a3d41")])
            self.option_add("*Listbox*Background", bg)
            self.option_add("*Listbox*Foreground", fg)
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        mbar = tk.Menu(self)
        file_m = tk.Menu(mbar, tearoff=0)
        file_m.add_command(label="Load Game Data (.pak)", command=self._load_pak)
        file_m.add_separator()
        file_m.add_command(label="Save Project (.dl3mod)", command=self._save_project)
        file_m.add_command(label="Load Project (.dl3mod)", command=self._load_project)
        file_m.add_command(label="Pack Mod to .pak File", command=self._pack_pak)
        file_m.add_separator()
        file_m.add_command(label="Settings", command=self._open_settings)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self._on_close)
        mbar.add_cascade(label="File", menu=file_m)
        self.config(menu=mbar)

        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main, padding=6); main.add(left, weight=1)
        ttk.Label(left, text="File Explorer", style="Header.TLabel").pack(anchor="w", pady=(0,4))
        
        search_frame = ttk.Frame(left)
        search_frame.pack(fill=tk.X, pady=(0, 6))
        self.file_search_var = tk.StringVar()
        self.file_search_var.trace_add("write", self._on_file_search_change)
        self.file_search_entry = ttk.Entry(search_frame, textvariable=self.file_search_var)
        self.file_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=0)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(tree_frame, columns=("abspath",), show="tree", yscrollcommand=scrollbar.set)
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        center = ttk.Frame(main, padding=6); main.add(center, weight=3)
        self.preview_label = ttk.Label(center, text="Previewing: —", style="Header.TLabel")
        self.preview_label.pack(anchor="w", pady=(0,4))
        preview_frame = ttk.Frame(center)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient="vertical")
        preview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt = tk.Text(preview_frame, wrap="none", font=("Consolas", 10), yscrollcommand=preview_scrollbar.set)
        self.txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preview_scrollbar.config(command=self.txt.yview)
        self.txt.bind("<Double-Button-1>", self._on_preview_double_click)
        self.txt.tag_configure("highlight", background="#4a4d51" if self.settings.dark_mode else "#d3d3d3")

        right = ttk.Frame(main, padding=6); main.add(right, weight=2)
        grp1 = ttk.Labelframe(right, text="1. Enter search terms (e.g., pistol ammo price):")
        grp1.pack(fill=tk.X, pady=(0,6))
        row = ttk.Frame(grp1); row.pack(fill=tk.X, padx=6, pady=6)
        self.ent_search = ttk.Entry(row)
        self.ent_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,8))
        self.ent_search.bind("<Return>", lambda event: self._find_params())
        ttk.Button(row, text="Find", command=self._find_params).pack(side=tk.LEFT)

        grp2 = ttk.Labelframe(right, text="2. Search Results (Click to preview, Double-click to add):")
        grp2.pack(fill=tk.BOTH, expand=True, pady=(0,6))
        list_frame2 = ttk.Frame(grp2)
        list_frame2.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        scrollbar2 = ttk.Scrollbar(list_frame2, orient="vertical")
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.lst_results = tk.Listbox(list_frame2, height=10, yscrollcommand=scrollbar2.set)
        self.lst_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar2.config(command=self.lst_results.yview)
        self.lst_results.bind("<Double-Button-1>", self._on_add_from_result)
        self.lst_results.bind("<ButtonRelease-1>", self._on_result_select)

        grp3 = ttk.Labelframe(right, text="3. Active Edits (Click to preview, Double-click to toggle):")
        grp3.pack(fill=tk.BOTH, expand=True)
        list_frame3 = ttk.Frame(grp3)
        list_frame3.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6,2))
        scrollbar3 = ttk.Scrollbar(list_frame3, orient="vertical")
        scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
        self.lst_edits = tk.Listbox(list_frame3, height=10, yscrollcommand=scrollbar3.set)
        self.lst_edits.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar3.config(command=self.lst_edits.yview)
        self.lst_edits.bind("<Button-3>", self._edits_context)
        self.lst_edits.bind("<Double-Button-1>", lambda _e: self._toggle_selected_edit())
        self.lst_edits.bind("<ButtonRelease-1>", self._on_edit_select)
        btns = ttk.Frame(grp3); btns.pack(fill=tk.X, padx=6, pady=(0,6))
        ttk.Button(btns, text="Toggle Enable", command=self._toggle_selected_edit).pack(side=tk.LEFT)
        ttk.Button(btns, text="Delete", command=self._delete_selected_edit).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Clear All", command=self._clear_edits).pack(side=tk.LEFT)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status).pack(anchor="w", padx=8, pady=(0,6))

    def _animate_spinner(self):
        if self.progress_win and hasattr(self, 'spinner_canvas'):
            self.spinner_canvas.itemconfig(self.spinner_arc, start=self.spinner_angle)
            self.spinner_angle = (self.spinner_angle + 10) % 360
            self.spinner_job = self.after(50, self._animate_spinner)

    def _show_progress(self, text: str, indeterminate: bool = True):
        if self.progress_win: return
        self.progress_win = tk.Toplevel(self)
        self.progress_win.title("Processing...")
        self.progress_win.transient(self)
        self.progress_win.grab_set()
        self.progress_win.resizable(False, False)
        frm = ttk.Frame(self.progress_win, padding=20); frm.pack()
        self.progress_label = ttk.Label(frm, text=text); self.progress_label.pack(pady=(0, 10))
        if indeterminate:
            bg_color = self.cget('bg') if not self.settings.dark_mode else "#1f2125"
            self.spinner_canvas = tk.Canvas(frm, width=40, height=40, bg=bg_color, highlightthickness=0)
            self.spinner_canvas.pack(pady=10)
            self.spinner_arc = self.spinner_canvas.create_arc(5, 5, 35, 35, start=0, extent=120, style=tk.ARC, width=4, outline="#4a90e2")
            self._animate_spinner()
        self.update_idletasks()
        x = self.winfo_x()+(self.winfo_width()//2)-(self.progress_win.winfo_width()//2)
        y = self.winfo_y()+(self.winfo_height()//2)-(self.progress_win.winfo_height()//2)
        self.progress_win.geometry(f"+{x}+{y}")
        self.update_idletasks()

    def _hide_progress(self):
        if self.spinner_job: self.after_cancel(self.spinner_job); self.spinner_job = None
        if self.progress_win: self.progress_win.destroy(); self.progress_win = None

    def _set_status(self, msg: str) -> None:
        self.status.set(msg)
        self.update_idletasks()

    def _load_pak(self) -> None:
        p = filedialog.askopenfilename(initialdir=self.settings.last_pak_dir, title="Open Game Data (.pak)", filetypes=[("PAK/ZIP","*.pak *.zip"),("All files","*.*")])
        if not p: return
        self.settings.last_pak_dir = str(Path(p).parent); self.settings.save()
        self._cleanup_temp()
        self._show_progress("Extracting game data...")
        threading.Thread(target=self._extract_and_populate, args=(p,)).start()

    def _extract_and_populate(self, pak_path: str):
        try:
            self.temp_root = Path(tempfile.mkdtemp(prefix="dltb_data_"))
            with zipfile.ZipFile(pak_path, "r") as zf: zf.extractall(self.temp_root)
            self.after(0, self._finish_loading, Path(pak_path).name)
        except Exception as e:
            self.after(0, self._loading_failed, e)

    def _finish_loading(self, pak_name: str):
        self._populate_tree(self.temp_root)
        self._hide_progress()
        self._set_status(f"Loaded {pak_name}")

    def _loading_failed(self, error: Exception):
        self._hide_progress(); self._cleanup_temp()
        messagebox.showerror(APP_NAME, f"Failed to open: {error}")

    def _cleanup_temp(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.txt.delete("1.0", tk.END)
        self.preview_label.config(text="Previewing: —")
        self.search_results.clear(); self.lst_results.delete(0, tk.END)
        self.active_edits.clear(); self.lst_edits.delete(0, tk.END)
        self.path_to_id.clear()
        if self.temp_root and self.temp_root.exists(): shutil.rmtree(self.temp_root, ignore_errors=True)
        self.temp_root = None; self.current_file = None

    def _populate_tree(self, root: Path) -> None:
        self.path_to_id.clear()
        root_id = self.tree.insert("", tk.END, text=root.name, values=(str(root),), open=True)
        self.path_to_id[root] = root_id
        for dirpath, dirnames, filenames in os.walk(root):
            parent_path = Path(dirpath)
            parent_id = self.path_to_id.get(parent_path)
            if parent_id is None: continue
            dirnames.sort(); filenames.sort()
            for dirname in dirnames:
                full_path = parent_path / dirname
                child_id = self.tree.insert(parent_id, tk.END, text=dirname, values=(str(full_path),))
                self.path_to_id[full_path] = child_id
            for filename in filenames:
                full_path = parent_path / filename
                item_id = self.tree.insert(parent_id, tk.END, text=filename, values=(str(full_path),))
                self.path_to_id[full_path] = item_id

    def _on_tree_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel: return
        try: abspath = self.tree.set(sel[0], "abspath")
        except tk.TclError: return
        p = Path(abspath)
        if p.is_dir() or self.current_file == p: return
        self._on_tree_select_path(p)

    def _on_tree_select_path(self, path: Path):
        self.current_file = path
        label = str(path.relative_to(self.temp_root)) if self.temp_root else path.name
        self.preview_label.config(text=f"Previewing: {label}")
        try: content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e: content = f"<Error reading file: {e}>"
        self.txt.delete("1.0", tk.END); self.txt.insert("1.0", content)
        self.txt.tag_remove("highlight", "1.0", tk.END)

    def _on_file_search_change(self, *args):
        if self._search_after_id: self.after_cancel(self._search_after_id)
        self._search_after_id = self.after(300, self._filter_file_tree)

    def _filter_file_tree(self):
        query = self.file_search_entry.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        if not self.temp_root: return
        if not query: self._populate_tree(self.temp_root); return
        paths_to_display = set()
        for path_obj in self.path_to_id:
            if query in path_obj.name.lower():
                paths_to_display.add(path_obj)
                parent = path_obj.parent
                while parent and (parent == self.temp_root or self.temp_root in parent.parents):
                    paths_to_display.add(parent)
                    parent = parent.parent
        sorted_paths = sorted(list(paths_to_display), key=lambda p: len(p.parts))
        filtered_path_to_id = {}
        for path in sorted_paths:
            parent_id = "" if path == self.temp_root else filtered_path_to_id.get(path.parent, "")
            new_id = self.tree.insert(parent_id, tk.END, text=path.name, values=(str(path),), open=True)
            filtered_path_to_id[path] = new_id

    def _on_preview_double_click(self, _evt=None) -> None:
        if not self.current_file: return
        
        index = self.txt.index(f"@{self.txt.winfo_pointerx()-self.txt.winfo_rootx()},{self.txt.winfo_pointery()-self.txt.winfo_rooty()}")
        ln = int(index.split(".")[0]) - 1
        line = self.txt.get(f"{ln+1}.0", f"{ln+1}.end")

        m_block = BLOCK_HEADER_RE.search(line)
        if m_block:
            lines = self.txt.get("1.0", "end-1c").splitlines()
            end_ln = find_block_bounds(lines, ln)
            if end_ln != -1:
                block_type, block_name = m_block.groups()
                description = f'{block_type}: "{block_name}"'
                if messagebox.askyesno("Confirm Block Deletion", f"Mark this entire block for deletion?\n\n{description}"):
                    edit = ModEdit(str(self.current_file), ln, f'Block("{block_name}")', "<DELETED>", description, block_type, edit_type='BLOCK_DELETE', end_line_number=end_ln)
                    self.active_edits[edit.key()] = edit
                    self._refresh_edits_list()
                return

        candidate: Optional[ModEdit] = None
        m_param = PARAM_RE.search(line)
        m_prop = PROP_RE.search(line)

        if m_param:
            pname, val = m_param.groups()
            candidate = ModEdit(str(self.current_file), ln, val, val, pname, pname)
        elif m_prop:
            pname, oval = m_prop.groups()
            oval = oval.strip()
            context = self._find_context_name(ln)
            candidate = ModEdit(str(self.current_file), ln, oval, oval, context or pname, pname)

        if not candidate: return
        default = candidate.current_value
        if default.startswith('"') and default.endswith('"') and ',' not in default:
             default = default[1:-1]

        new_val = simpledialog.askstring("Add/Edit", f"Enter new value for {candidate.param_name}:", initialvalue=default)
        if new_val is None: return
        
        is_string_type = candidate.original_value.startswith('"')
        final = new_val
        if is_string_type and not (new_val.startswith('"') and new_val.endswith('"')):
             if ',' not in new_val: final = f'"{new_val}"'

        key = candidate.key()
        if key in self.active_edits: self.active_edits[key].current_value = final
        else: candidate.current_value = final; self.active_edits[key] = candidate
        self._refresh_edits_list()

    def _find_context_name(self, from_line: int) -> Optional[str]:
        lines = self.txt.get("1.0","end").splitlines()
        for i in range(from_line, -1, -1):
            m = HEADER_RE.search(lines[i])
            if m: return m.group(2)
        return None
    
    def _show_edit_in_preview(self, edit: ModEdit):
        if not edit: return
        file_path = Path(edit.file_path)
        def highlight():
            self.txt.tag_remove("highlight", "1.0", tk.END)
            start_index = f"{edit.line_number + 1}.0"
            end_index = f"{edit.end_line_number + 1}.end"
            self.txt.see(start_index)
            self.txt.tag_add("highlight", start_index, end_index)

        if self.current_file != file_path:
            item_id = self.path_to_id.get(file_path)
            if item_id and self.tree.exists(item_id):
                self.tree.selection_set(item_id); self.tree.focus(item_id); self.tree.see(item_id)
                self.after(50, highlight)
            else: self._on_tree_select_path(file_path); self.after(50, highlight)
        else:
            highlight()

    def _find_params(self) -> None:
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load a game data .pak first."); return
        query = self.ent_search.get().strip().lower()
        if not query: messagebox.showinfo(APP_NAME, "Please enter one or more search terms."); return
        kws = query.split()
        self.lst_results.delete(0, tk.END); self.search_results.clear()
        scr_files = [p for p in self.path_to_id if p.name.endswith(".scr")]
        if not scr_files: self._set_status("No .scr files to search."); return
        self._show_progress("Searching...")
        threading.Thread(target=self._run_search_in_background, args=(scr_files, kws)).start()

    def _run_search_in_background(self, scr_files: List[Path], kws: List[str]):
        scan_func = partial(scan_scr_for_hits, kws=kws)
        results = []
        try:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                for future in concurrent.futures.as_completed([executor.submit(scan_func, f) for f in scr_files]):
                    results.extend(future.result())
        except Exception:
            results = [item for f in scr_files for item in scan_func(f)]
        finally:
            self.after(0, self._finish_search, results)

    def _finish_search(self, results: List[ModEdit]):
        self._hide_progress()
        uniq = list({ed.key(): ed for ed in results}.values())
        uniq.sort(key=lambda e: (e.edit_type, Path(e.file_path).name.lower(), e.description.lower(), e.param_name.lower()))
        self.search_results = uniq
        for ed in self.search_results:
            label = f'[BLOCK] {ed.description}' if ed.edit_type == 'BLOCK_DELETE' else f"Item: {ed.description} -> {ed.param_name}"
            self.lst_results.insert(tk.END, label)
        self._set_status(f"Found {len(self.search_results)} match(es).")

    def _on_result_select(self, _evt=None) -> None:
        sel = self.lst_results.curselection()
        if not sel: return
        self._show_edit_in_preview(self.search_results[sel[0]])
        
    def _on_add_from_result(self, _evt=None) -> None:
        sel = self.lst_results.curselection()
        if not sel: return
        ed = self.search_results[sel[0]]

        if ed.edit_type == 'BLOCK_DELETE':
            if messagebox.askyesno("Confirm Deletion", f"Mark this entire block for deletion?\n\n{ed.description}"):
                self.active_edits[ed.key()] = ed
                self._refresh_edits_list()
            return

        default = ed.current_value
        if default.startswith('"') and default.endswith('"') and ',' not in default:
             default = default[1:-1]
        new_val = simpledialog.askstring("Add to Mod", f"Enter new value for {ed.param_name}:", initialvalue=default)
        if new_val is None: return
        is_string_type = ed.original_value.startswith('"')
        final = new_val
        if is_string_type and not (new_val.startswith('"') and new_val.endswith('"')):
             if ',' not in new_val: final = f'"{new_val}"'
        ed.current_value = final
        self.active_edits[ed.key()] = ed
        self._refresh_edits_list()

    def _refresh_edits_list(self) -> None:
        self.lst_edits.delete(0, tk.END)
        for ed in sorted(self.active_edits.values(), key=lambda e:(e.edit_type, e.description.lower(), e.param_name.lower())):
            chk = "☑" if ed.is_enabled else "☐"
            shown = f'{chk} [DELETE BLOCK] {ed.description}' if ed.edit_type == 'BLOCK_DELETE' else f"{chk}  {ed.description}: {ed.param_name} = {ed.current_value}  (was {ed.original_value})"
            self.lst_edits.insert(tk.END, shown)

    def _selected_edit(self) -> Optional[ModEdit]:
        sel = self.lst_edits.curselection()
        if not sel: return None
        ordered = sorted(self.active_edits.values(), key=lambda e:(e.edit_type, e.description.lower(), e.param_name.lower()))
        try: return ordered[sel[0]]
        except IndexError: return None

    def _on_edit_select(self, _evt=None) -> None:
        edit = self._selected_edit()
        if edit: self._show_edit_in_preview(edit)

    def _toggle_selected_edit(self) -> None:
        ed = self._selected_edit()
        if ed: ed.is_enabled = not ed.is_enabled; self._refresh_edits_list()

    def _delete_selected_edit(self) -> None:
        ed = self._selected_edit()
        if ed: del self.active_edits[ed.key()]; self._refresh_edits_list()

    def _clear_edits(self) -> None:
        if not self.active_edits or not messagebox.askyesno(APP_NAME, "Clear all edits?"): return
        self.active_edits.clear(); self._refresh_edits_list()

    def _edits_context(self, event) -> None:
        self.lst_edits.selection_clear(0, tk.END); self.lst_edits.selection_set(self.lst_edits.nearest(event.y)); self.lst_edits.activate(self.lst_edits.nearest(event.y))
        if not self.lst_edits.curselection(): return
        
        edit = self._selected_edit()
        if not edit: return
        
        menu = tk.Menu(self, tearoff=0)
        if edit.edit_type == 'VALUE_REPLACE':
            menu.add_command(label="Edit Value", command=self._edit_selected_value)
            menu.add_separator()
        
        menu.add_command(label="Toggle Enable", command=self._toggle_selected_edit)
        menu.add_command(label="Delete", command=self._delete_selected_edit)
        menu.post(event.x_root, event.y_root)

    def _edit_selected_value(self) -> None:
        ed = self._selected_edit()
        if not ed or ed.edit_type != 'VALUE_REPLACE':
            return

        initial_val = ed.current_value
        if initial_val.startswith('"') and initial_val.endswith('"') and ',' not in initial_val:
             initial_val = initial_val[1:-1]

        new_val = simpledialog.askstring("Edit Value", f"Enter new value for {ed.param_name}:", initialvalue=initial_val)
        if new_val is None:
            return

        is_string_type = ed.original_value.startswith('"')
        final = new_val
        if is_string_type and not (new_val.startswith('"') and new_val.endswith('"')):
             if ',' not in new_val:
                 final = f'"{new_val}"'

        ed.current_value = final
        self._refresh_edits_list()

    def _save_project(self) -> None:
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load a game data (.pak) first."); return
        p = filedialog.asksaveasfilename(defaultextension=".dl3mod", filetypes=[("DL3 Mod Project","*.dl3mod")])
        if not p: return
        payload = {"edits": [
            {**ed.__dict__, "file_path": str(Path(ed.file_path).relative_to(self.temp_root))}
            for ed in self.active_edits.values()
        ]}
        write_json(Path(p), payload)
        messagebox.showinfo(APP_NAME, "Project saved.")

    def _load_project(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("DL3 Mod Project","*.dl3mod")])
        if not p: return
        data = read_json(Path(p), None)
        if not data or "edits" not in data: messagebox.showerror(APP_NAME, "Invalid project file."); return
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load a game data (.pak) first, then load the project."); return
        self.active_edits.clear()
        for d in data["edits"]:
            me = ModEdit(file_path=str(self.temp_root / d["file_path"]), **{k:v for k,v in d.items() if k != "file_path"})
            self.active_edits[me.key()] = me
        self._refresh_edits_list()
        messagebox.showinfo(APP_NAME, "Project loaded.")

    def _pack_pak(self) -> None:
        if not self.active_edits: messagebox.showwarning(APP_NAME, "No active edits to pack."); return
        out = filedialog.asksaveasfilename(defaultextension=".pak", filetypes=[("PAK files","*.pak")])
        if not out: return
        
        edits_by_file: Dict[str, List[ModEdit]] = {}
        for ed in self.active_edits.values():
            if ed.is_enabled: edits_by_file.setdefault(ed.file_path, []).append(ed)
        
        try:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
                for fpath, edits in edits_by_file.items():
                    p = Path(fpath)
                    lines_to_delete = set()
                    value_edits = []
                    for edit in edits:
                        if edit.edit_type == 'BLOCK_DELETE': lines_to_delete.update(range(edit.line_number, edit.end_line_number + 1))
                        else: value_edits.append(edit)
                    
                    modified_lines = p.read_text(encoding="utf-8", errors="ignore").splitlines(True)
                    for e in sorted(value_edits, key=lambda x: x.line_number):
                        if e.line_number >= len(modified_lines): continue
                        orig = modified_lines[e.line_number]
                        m = PARAM_RE.search(orig)
                        if m and e.param_name == m.group(1):
                            before=f'Param("{e.param_name}", {e.original_value})'; after=f'Param("{e.param_name}", {e.current_value})'
                            modified_lines[e.line_number] = orig.replace(before, after, 1)
                        else:
                            pm = PROP_RE.search(orig)
                            if pm and pm.group(1) == e.param_name:
                                start, end = orig.find("("), orig.rfind(")")
                                if -1 < start < end:
                                    modified_lines[e.line_number] = f"{orig[:start+1]}{e.current_value}{orig[end:]}"
                            else: modified_lines[e.line_number] = orig.replace(e.original_value, e.current_value, 1)

                    final_content = "".join([line for i, line in enumerate(modified_lines) if i not in lines_to_delete])
                    rel = str(p.relative_to(self.temp_root)) if self.temp_root else p.name
                    zf.writestr(rel.replace(os.sep, "/"), final_content.encode("utf-8"))
            messagebox.showinfo(APP_NAME, f"Packed mod: {out}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to pack: {e}")

    def _open_settings(self) -> None:
        win = tk.Toplevel(self); win.title("Settings"); win.transient(self)
        frm = ttk.Frame(win, padding=8); frm.pack(fill=tk.BOTH, expand=True)
        v_last = tk.StringVar(value=self.settings.last_pak_dir); v_dark = tk.BooleanVar(value=self.settings.dark_mode)
        r = ttk.Frame(frm); r.pack(fill=tk.X, pady=4)
        ttk.Label(r, text="Default Folder:", width=14).pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=v_last).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(r, text="Browse…", command=lambda: self._pick_dir(v_last)).pack(side=tk.LEFT)
        ttk.Checkbutton(frm, text="Dark mode (restart required)", variable=v_dark).pack(anchor="w", pady=(6,0))
        ttk.Button(frm, text="Save", command=lambda: self._save_settings_and_close(win, v_last, v_dark)).pack(anchor="e", pady=(10,0))

    def _pick_dir(self, var: tk.StringVar) -> None:
        p = filedialog.askdirectory();
        if p: var.set(p)

    def _save_settings_and_close(self, win: tk.Toplevel, v_last: tk.StringVar, v_dark: tk.BooleanVar) -> None:
        self.settings.last_pak_dir = v_last.get().strip() or self.settings.last_pak_dir
        self.settings.dark_mode = v_dark.get()
        self.settings.save(); win.destroy()

    def _on_close(self) -> None:
        if self.active_edits:
            if not messagebox.askyesno("Quit", "You have unsaved edits. Are you sure you want to quit?"):
                return
        self._cleanup_temp()
        self.destroy()

def main() -> None:
    if sys.platform.startswith('win'):
        import multiprocessing
        multiprocessing.freeze_support()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
