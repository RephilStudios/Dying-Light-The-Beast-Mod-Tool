# file: DLTB_All_in_One_v22.py
"""
DLTB All in One — Tkinter Single-File Script Editor & Packer

Matches the classic 3-column UI:
- Left: 'Load Game Data (.pak)' + folder tree.
- Center: live preview of the selected file; double-click a line to add/edit.
- Right: (1) search inputs, (2) results, (3) active edits with enable/disable checkboxes; pack button.

Notes
- Treats .pak as a ZIP container.
- No external deps; optional CLI '7z' NOT required here.
- v22: Makes the central text preview read-only to prevent accidental edits.
       Modifications are now exclusively handled through double-clicking and the right-side panel.
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
from tkinter.colorchooser import askcolor

APP_NAME = "Dying Light The Beast Mod Tool"
APP_DIR = Path.home() / ".dltb_all_in_one"
CONFIG_PATH = APP_DIR / "config.json"

# Regexes for simple, robust matching in .scr files.
PARAM_RE = re.compile(r'Param\("([^"]+)",\s*(".*?"|\S+)\)\s*;')
PROP_RE  = re.compile(r'^\s*(?!Param\b)(\w+)\s*\((.*)\)\s*;')
BLOCK_HEADER_RE = re.compile(r'^\s*(AttackPreset)\s*\(\s*"([^"]+)"\s*\)')


def _find_block_context_name(target_line: int, lines: List[str]) -> Optional[str]:
    """
    Finds the name of the block containing target_line. Used for single lookups from the UI.
    Scans upwards, tracking brace depth, to find the block header.
    It prioritizes the first quoted string in the header's parameters as the name.
    If none is found, it uses the first unquoted parameter.
    If that fails, it uses the block type itself (e.g., "Item").
    """
    brace_depth = 0
    # Scan upwards from the line *before* the target.
    for i in range(target_line - 1, -1, -1):
        line = lines[i]
        brace_depth += line.count('}')
        brace_depth -= line.count('{')

        # When brace_depth becomes negative, we have found the '{' that opens the containing block.
        if brace_depth < 0:
            # The header is likely on this line or a few lines above.
            # Combine a few lines to handle multi-line declarations.
            search_area = " ".join(lines[max(0, i - 4) : i + 1])
            
            # Look for the pattern: BlockType(...)
            # Use finditer to get the last match, as it's closest to the block opening.
            last_match = None
            for m in re.finditer(r'(\w+)\s*\(([^)]*)\)', search_area.replace('\n', ' ')):
                last_match = m
            match = last_match

            if match:
                block_type = match.group(1)
                params_str = match.group(2)

                # Priority 1: Find the first quoted string.
                quoted_match = re.search(r'"([^"]+)"', params_str)
                if quoted_match:
                    return quoted_match.group(1).strip()

                # Priority 2: Find the first unquoted parameter if it's a valid identifier.
                unquoted_match = re.match(r'\s*([a-zA-Z0-9_]+)', params_str)
                if unquoted_match:
                    return unquoted_match.group(1).strip()

                # Priority 3: Fallback to the block type.
                return block_type
            
            # Fallback for simple headers like 'sub SubName {'
            simple_match = re.search(r'sub\s+([a-zA-Z0-9_]+)', search_area.replace('\n', ' '))
            if simple_match:
                return simple_match.group(1).strip()

            # Found the block but no recognizable header, stop searching upwards for this context.
            return None
            
    return None # Scanned to top of file without finding context

# ------------------------------ Model ----------------------------------------- #

class ModEdit:
    """A single change: value replacement, block deletion, or line deletion."""
    def __init__(
        self,
        file_path: str,
        line_number: int,
        original_value: str,
        current_value: str,
        description: str,
        param_name: str,
        is_param: bool = False,
        is_enabled: bool = True,
        edit_type: Literal['VALUE_REPLACE', 'BLOCK_DELETE', 'LINE_DELETE'] = 'VALUE_REPLACE',
        end_line_number: int = -1,
    ) -> None:
        self.file_path = file_path
        self.line_number = line_number
        self.original_value = original_value
        self.current_value = current_value
        self.description = description
        self.param_name = param_name
        self.is_param = is_param
        self.is_enabled = is_enabled
        self.edit_type = edit_type
        self.end_line_number = end_line_number if end_line_number != -1 else line_number

    def key(self) -> Tuple[str, int]:
        return (self.file_path, self.line_number)

class EditDialog(simpledialog.Dialog):
    """Custom dialog for editing a property's value and its description."""
    def __init__(self, parent, title, param_name, initial_desc, initial_val):
        self.param_name = param_name
        self.initial_desc = initial_desc
        self.initial_val = initial_val
        self.result: Optional[Tuple[str, str]] = None
        super().__init__(parent, title)

    def body(self, master):
        self.configure(bg=master.cget('bg'))
        # Description field
        ttk.Label(master, text=f"Parent/Description for '{self.param_name}':").grid(row=0, sticky="w", padx=5, pady=2)
        self.desc_entry = ttk.Entry(master, width=50)
        self.desc_entry.grid(row=1, padx=5, pady=(2, 8))
        self.desc_entry.insert(0, self.initial_desc)

        # Value field
        ttk.Label(master, text="New Value:").grid(row=2, sticky="w", padx=5, pady=2)
        self.val_entry = ttk.Entry(master, width=50)
        self.val_entry.grid(row=3, padx=5, pady=2)
        self.val_entry.insert(0, self.initial_val)
        return self.val_entry

    def apply(self):
        self.result = (self.desc_entry.get(), self.val_entry.get())


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
        home_dir = str(Path.home())
        self.last_pak_dir: str = data.get("last_pak_dir", home_dir)
        self.last_project_dir: str = data.get("last_project_dir", home_dir)
        self.dark_mode: bool = bool(data.get("dark_mode", False))
        
        colors = data.get("colors", {})
        self.colors = {
            "light": {
                "param": colors.get("light", {}).get("param", "#0000ff"),
                "prop": colors.get("light", {}).get("prop", "#267f99"),
                "block_header": colors.get("light", {}).get("block_header", "#a31515"),
            },
            "dark": {
                "param": colors.get("dark", {}).get("param", "#569cd6"),
                "prop": colors.get("dark", {}).get("prop", "#4ec9b0"),
                "block_header": colors.get("dark", {}).get("block_header", "#c586c0"),
            }
        }

    def save(self) -> None:
        write_json(CONFIG_PATH, {
            "last_pak_dir": self.last_pak_dir,
            "last_project_dir": self.last_project_dir,
            "dark_mode": self.dark_mode,
            "colors": self.colors,
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
            brace_depth += line_content.count('{')
        brace_depth -= line_content.count('}')
        if has_opened and brace_depth <= 0:
            return i
    return -1

def scan_scr_for_hits(file_path: Path, kws: List[str]) -> List[ModEdit]:
    """
    Optimized single-pass scanner. Finds Param/Property/Block matches in one .scr file.
    It iterates through the file once, tracking block context with a stack, which is much
    faster than re-scanning for the context of every match.
    """
    hits: List[ModEdit] = []
    if not kws: return hits
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return hits
    
    context_stack: List[str] = []
    level_stack: List[int] = [] # Tracks the brace level for each context on the stack
    brace_level = 0
    potential_header_buffer: List[str] = []

    for ln, line in enumerate(lines):
        stripped = line.strip()
        
        # 1. Pop contexts that are closed by a '}' on this line.
        # A context at level N is closed when the brace_level drops below N.
        if '}' in line:
            brace_level -= line.count('}')
            while level_stack and brace_level < level_stack[-1]:
                level_stack.pop()
                context_stack.pop()
        
        # 2. Check for property hits on the current line using the current context.
        current_context = context_stack[-1] if context_stack else None
        
        if m_block := BLOCK_HEADER_RE.search(line):
            block_type, block_name = m_block.groups()
            search_context = f"{block_type.lower()} {block_name.lower()}"
            if all(kw in search_context for kw in kws):
                end_ln = find_block_bounds(lines, ln)
                if end_ln != -1:
                    hits.append(ModEdit(str(file_path), ln, f'Block("{block_name}")', "<DELETED>", f'{block_type}: "{block_name}"', block_type, edit_type='BLOCK_DELETE', end_line_number=end_ln))

        if m_param := PARAM_RE.search(line):
            pname, val = m_param.groups()
            search_context = (current_context or "").lower() + " " + pname.lower()
            if all(kw in search_context for kw in kws):
                hits.append(ModEdit(str(file_path), ln, val, val, current_context or pname, pname, is_param=True))

        if pm := PROP_RE.search(line):
            pname, oval = pm.groups()
            search_context = (current_context or "").lower() + " " + pname.lower()
            if all(kw in search_context for kw in kws):
                hits.append(ModEdit(str(file_path), ln, oval.strip(), oval.strip(), current_context or Path(file_path).stem, pname, is_param=False))

        # 3. Buffer potential header lines.
        if stripped and not stripped.startswith(('//', '#')):
             potential_header_buffer.append(stripped)

        # 4. If an opening brace is found, process the buffer to find and push the new context.
        if '{' in line:
            header_text = " ".join(potential_header_buffer)
            name = None
            last_match = None
            for m in re.finditer(r'(\w+)\s*\(([^)]*)\)', header_text):
                last_match = m
            
            if last_match:
                block_type, params_str = last_match.groups()
                quoted_match = re.search(r'"([^"]+)"', params_str)
                if quoted_match: name = quoted_match.group(1).strip()
                else:
                    unquoted_match = re.match(r'\s*([a-zA-Z0-9_]+)', params_str)
                    if unquoted_match: name = unquoted_match.group(1).strip()
                    else: name = block_type
            else:
                simple_match = re.search(r'sub\s+([a-zA-Z0-9_]+)', header_text)
                if simple_match: name = simple_match.group(1).strip()
            
            if name:
                # Push context and its brace level *before* adding the current line's '{'
                context_stack.append(name)
                level_stack.append(brace_level)

            potential_header_buffer = [] # Clear buffer after processing
            brace_level += line.count('{')
        
        # If a line contains a property, it's not a header line, so clear buffer.
        elif stripped and (PROP_RE.search(stripped) or PARAM_RE.search(stripped)):
            potential_header_buffer = []
            
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
        self._configure_text_tags()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try: style.theme_use("clam")
        except Exception: pass
        if self.settings.dark_mode:
            bg, fg = "#1f2125", "#e7e7e7"
            self.configure(bg=bg)
            for cls in ["TFrame","TLabel","TButton","TEntry","Treeview","TNotebook","TLabelframe","TLabelframe.Label", "Listbox"]:
                style.configure(cls, background=bg, foreground=fg, fieldbackground=bg)
            style.map("Treeview", background=[("selected","#3a3d41")])
            self.option_add("*Listbox*Background", bg); self.option_add("*Listbox*Foreground", fg)
            self.option_add("*Dialog*Background", bg)
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
        
        settings_m = tk.Menu(mbar, tearoff=0)
        settings_m.add_command(label="General", command=self._open_settings)
        settings_m.add_command(label="Highlighting Colors", command=self._open_color_settings)
        
        file_m.add_cascade(label="Settings", menu=settings_m)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self._on_close)
        mbar.add_cascade(label="File", menu=file_m)

        help_m = tk.Menu(mbar, tearoff=0)
        help_m.add_command(label="About / Help", command=self._show_help_window)
        mbar.add_cascade(label="Help", menu=help_m)
        self.config(menu=mbar)

        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL); main.pack(fill=tk.BOTH, expand=True)
        left = ttk.Frame(main, padding=6); main.add(left, weight=1)
        ttk.Label(left, text="File Explorer", style="Header.TLabel").pack(anchor="w", pady=(0,4))
        search_frame = ttk.Frame(left); search_frame.pack(fill=tk.X, pady=(0, 6))
        self.file_search_var = tk.StringVar(); self.file_search_var.trace_add("write", self._on_file_search_change)
        self.file_search_entry = ttk.Entry(search_frame, textvariable=self.file_search_var)
        self.file_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tree_frame = ttk.Frame(left); tree_frame.pack(fill=tk.BOTH, expand=True, pady=0)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree = ttk.Treeview(tree_frame, columns=("abspath",), show="tree", yscrollcommand=scrollbar.set)
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        center = ttk.Frame(main, padding=6); main.add(center, weight=3)
        self.preview_label = ttk.Label(center, text="Previewing: —", style="Header.TLabel")
        self.preview_label.pack(anchor="w", pady=(0,4))
        preview_frame = ttk.Frame(center); preview_frame.pack(fill=tk.BOTH, expand=True)
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient="vertical")
        preview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt = tk.Text(preview_frame, wrap="none", font=("Consolas", 10), yscrollcommand=preview_scrollbar.set, state=tk.DISABLED)
        self.txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preview_scrollbar.config(command=self.txt.yview)
        self.txt.bind("<Double-Button-1>", self._on_preview_double_click)
        self.txt.bind("<Button-3>", self._on_preview_right_click)
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
        list_frame2 = ttk.Frame(grp2); list_frame2.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        scrollbar2 = ttk.Scrollbar(list_frame2, orient="vertical"); scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
        self.lst_results = tk.Listbox(list_frame2, height=10, yscrollcommand=scrollbar2.set)
        self.lst_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar2.config(command=self.lst_results.yview)
        self.lst_results.bind("<Double-Button-1>", self._on_add_from_result)
        self.lst_results.bind("<ButtonRelease-1>", self._on_result_select)

        grp3 = ttk.Labelframe(right, text="3. Active Edits (Click to preview, Double-click to toggle):")
        grp3.pack(fill=tk.BOTH, expand=True)
        list_frame3 = ttk.Frame(grp3); list_frame3.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6,2))
        scrollbar3 = ttk.Scrollbar(list_frame3, orient="vertical"); scrollbar3.pack(side=tk.RIGHT, fill=tk.Y)
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

        self.status = tk.StringVar(value="Ready."); ttk.Label(self, textvariable=self.status).pack(anchor="w", padx=8, pady=(0,6))

    def _configure_text_tags(self):
        mode = "dark" if self.settings.dark_mode else "light"
        colors = self.settings.colors[mode]
        self.txt.tag_configure("param", foreground=colors["param"])
        self.txt.tag_configure("prop", foreground=colors["prop"])
        self.txt.tag_configure("block_header", foreground=colors["block_header"], font=("Consolas", 10, "bold"))

    def _apply_syntax_highlighting(self):
        self.txt.tag_remove("param", "1.0", tk.END); self.txt.tag_remove("prop", "1.0", tk.END); self.txt.tag_remove("block_header", "1.0", tk.END)
        content = self.txt.get("1.0", "end-1c")
        for i, line in enumerate(content.splitlines()):
            line_num_str = str(i + 1)
            for m in PARAM_RE.finditer(line):
                self.txt.tag_add("param", f"{line_num_str}.{m.start()}", f"{line_num_str}.{m.end()}")
            for m in PROP_RE.finditer(line):
                self.txt.tag_add("prop", f"{line_num_str}.{m.start()}", f"{line_num_str}.{m.end()}")
            for m in BLOCK_HEADER_RE.finditer(line):
                self.txt.tag_add("block_header", f"{line_num_str}.{m.start()}", f"{line_num_str}.{m.end()}")

    def _show_help_window(self):
        win = tk.Toplevel(self); win.title("About & Help"); win.transient(self)
        win.geometry("600x450"); win.resizable(False, False)
        bg = "#1f2125" if self.settings.dark_mode else "#f0f0f0"
        win.configure(bg=bg)
        main_frame = ttk.Frame(win, padding=15); main_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(main_frame, text=APP_NAME, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(main_frame, text="A tool for modifying Dying Light .scr files.", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 15))
        help_text = {
            "Params": 'e.g., Param("MaxAmmo", 30);\nThese are named values. Double-click to edit the value.',
            "Properties": 'e.g., Price(1500);\nThese are often found inside Item definitions. Double-click to edit the value.',
            "Blocks": 'e.g., AttackPreset("biter_grab") { ... }\nThese are multi-line blocks of code. You can search for them and mark the entire block for deletion from the search results, or by double-clicking the header line in the preview.'
        }
        for title, text in help_text.items():
            ttk.Label(main_frame, text=title, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(10, 2))
            ttk.Label(main_frame, text=text, wraplength=550, justify=tk.LEFT).pack(anchor="w")
        ttk.Button(main_frame, text="Close", command=win.destroy).pack(pady=(20,0)); win.grab_set()

    def _show_progress(self, text: str):
        if self.progress_win: return
        self.progress_win = tk.Toplevel(self); self.progress_win.title("Processing..."); self.progress_win.transient(self)
        self.progress_win.grab_set(); self.progress_win.resizable(False, False)
        frm = ttk.Frame(self.progress_win, padding=20); frm.pack()
        ttk.Label(frm, text=text).pack(pady=(0, 10))
        bg_color = "#1f2125" if self.settings.dark_mode else self.cget('bg')
        self.spinner_canvas = tk.Canvas(frm, width=40, height=40, bg=bg_color, highlightthickness=0)
        self.spinner_canvas.pack(pady=10)
        self.spinner_arc = self.spinner_canvas.create_arc(5, 5, 35, 35, start=0, extent=120, style=tk.ARC, width=4, outline="#4a90e2")
        self._animate_spinner()
        self.update_idletasks()
        x, y = self.winfo_x()+(self.winfo_width()//2), self.winfo_y()+(self.winfo_height()//2)
        self.progress_win.geometry(f"+{x - self.progress_win.winfo_width()//2}+{y - self.progress_win.winfo_height()//2}")

    def _animate_spinner(self):
        if self.progress_win and self.spinner_canvas.winfo_exists():
            self.spinner_canvas.itemconfig(self.spinner_arc, start=self.spinner_angle)
            self.spinner_angle = (self.spinner_angle + 10) % 360
            self.spinner_job = self.after(50, self._animate_spinner)

    def _hide_progress(self):
        if self.spinner_job: self.after_cancel(self.spinner_job); self.spinner_job = None
        if self.progress_win: self.progress_win.destroy(); self.progress_win = None

    def _load_pak(self) -> None:
        p = filedialog.askopenfilename(initialdir=self.settings.last_pak_dir, title="Open Game Data (.pak)", filetypes=[("PAK/ZIP","*.pak *.zip"),("All files","*.*")])
        if not p: return
        self.settings.last_pak_dir = str(Path(p).parent); self.settings.save()
        self._cleanup_temp(); self._show_progress("Extracting game data...")
        threading.Thread(target=self._extract_and_populate, args=(p,)).start()

    def _extract_and_populate(self, pak_path: str):
        try:
            self.temp_root = Path(tempfile.mkdtemp(prefix="dltb_data_"))
            with zipfile.ZipFile(pak_path, "r") as zf: zf.extractall(self.temp_root)
            self.after(0, self._finish_loading, Path(pak_path).name)
        except Exception as e: self.after(0, self._loading_failed, e)

    def _finish_loading(self, pak_name: str):
        self._populate_tree(self.temp_root); self._hide_progress(); self._set_status(f"Loaded {pak_name}")

    def _loading_failed(self, error: Exception):
        self._hide_progress(); self._cleanup_temp(); messagebox.showerror(APP_NAME, f"Failed to open: {error}")

    def _cleanup_temp(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.txt.config(state=tk.NORMAL)
        self.txt.delete("1.0", tk.END)
        self.txt.config(state=tk.DISABLED)
        self.preview_label.config(text="Previewing: —")
        self.search_results.clear()
        self.lst_results.delete(0, tk.END)
        self.active_edits.clear()
        self.lst_edits.delete(0, tk.END)
        self.path_to_id.clear()
        if self.temp_root and self.temp_root.exists():
            shutil.rmtree(self.temp_root, ignore_errors=True)
        self.temp_root = None
        self.current_file = None

    def _populate_tree(self, root: Path) -> None:
        self.path_to_id.clear()
        root_id = self.tree.insert("", tk.END, text=root.name, values=(str(root),), open=True)
        self.path_to_id[root] = root_id
        for dirpath, dirnames, filenames in os.walk(root):
            parent_path = Path(dirpath); parent_id = self.path_to_id.get(parent_path)
            if parent_id is None: continue
            dirnames.sort(); filenames.sort()
            for name in dirnames: self.path_to_id[parent_path / name] = self.tree.insert(parent_id, tk.END, text=name, values=(str(parent_path / name),))
            for name in filenames: self.path_to_id[parent_path / name] = self.tree.insert(parent_id, tk.END, text=name, values=(str(parent_path / name),))

    def _on_tree_select_path(self, path: Path):
        self.current_file = path
        label = str(path.relative_to(self.temp_root)) if self.temp_root else path.name
        self.preview_label.config(text=f"Previewing: {label}")
        try: content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e: content = f"<Error reading file: {e}>"
        
        self.txt.config(state=tk.NORMAL)
        self.txt.delete("1.0", tk.END)
        self.txt.insert("1.0", content)
        self.txt.tag_remove("highlight", "1.0", tk.END)
        self._apply_syntax_highlighting()
        self.txt.config(state=tk.DISABLED)

    def _on_tree_select(self, _evt=None) -> None:
        if not (sel := self.tree.selection()): return
        try: p = Path(self.tree.set(sel[0], "abspath"))
        except tk.TclError: return
        if not p.is_dir() and self.current_file != p: self._on_tree_select_path(p)

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
                    paths_to_display.add(parent); parent = parent.parent
        filtered_path_to_id = {}
        for path in sorted(list(paths_to_display), key=lambda p: len(p.parts)):
            parent_id = "" if path == self.temp_root else filtered_path_to_id.get(path.parent, "")
            filtered_path_to_id[path] = self.tree.insert(parent_id, tk.END, text=path.name, values=(str(path),), open=True)

    def _on_preview_double_click(self, _evt=None) -> None:
        if not self.current_file: return
        index = self.txt.index(f"@{self.txt.winfo_pointerx()-self.txt.winfo_rootx()},{self.txt.winfo_pointery()-self.txt.winfo_rooty()}")
        ln = int(index.split(".")[0]) - 1
        line = self.txt.get(f"{ln+1}.0", f"{ln+1}.end")

        if m_block := BLOCK_HEADER_RE.search(line):
            lines = self.txt.get("1.0", "end-1c").splitlines()
            if (end_ln := find_block_bounds(lines, ln)) != -1:
                block_type, block_name = m_block.groups()
                description = f'{block_type}: "{block_name}"'
                if messagebox.askyesno("Confirm Block Deletion", f"Mark this block for deletion?\n\n{description}"):
                    edit = ModEdit(str(self.current_file), ln, f'Block("{block_name}")', "<DELETED>", description, block_type, edit_type='BLOCK_DELETE', end_line_number=end_ln)
                    self.active_edits[edit.key()] = edit; self._refresh_edits_list()
                return

        candidate: Optional[ModEdit] = None
        if m_param := PARAM_RE.search(line):
            pname, val = m_param.groups()
            context = self._find_context_name(ln)
            candidate = ModEdit(str(self.current_file), ln, val, val, context or pname, pname, is_param=True)
        elif m_prop := PROP_RE.search(line):
            pname, oval = m_prop.groups()
            context = self._find_context_name(ln)
            candidate = ModEdit(str(self.current_file), ln, oval.strip(), oval.strip(), context or pname, pname, is_param=False)

        if not candidate: return
        
        # Prepare default value for dialog
        default_val = candidate.current_value
        if default_val.startswith('"') and default_val.endswith('"') and ',' not in default_val:
             default_val = default_val[1:-1]

        # Use the new custom dialog
        initial_desc = candidate.param_name if candidate.is_param else candidate.description
        dialog = EditDialog(self, "Add/Edit Property", candidate.param_name, initial_desc, default_val)
        if dialog.result is None: return # User cancelled

        new_desc, new_val_str = dialog.result
        
        final_val = new_val_str
        if candidate.original_value.startswith('"') and not (new_val_str.startswith('"') and new_val_str.endswith('"')) and ',' not in new_val_str:
            final_val = f'"{new_val_str}"'
        
        key = candidate.key()
        if key in self.active_edits:
            self.active_edits[key].current_value = final_val
            self.active_edits[key].description = new_desc # Update description too
        else:
            candidate.current_value = final_val
            candidate.description = new_desc # Update description
            self.active_edits[key] = candidate
        self._refresh_edits_list()

    def _find_context_name(self, target_line: int) -> Optional[str]:
        lines = self.txt.get("1.0","end-1c").splitlines()
        return _find_block_context_name(target_line, lines)
    
    def _on_preview_right_click(self, event):
        if not self.current_file: return

        index = self.txt.index(f"@{event.x},{event.y}")
        ln = int(index.split(".")[0]) - 1
        line = self.txt.get(f"{ln + 1}.0", f"{ln + 1}.end")

        if not (PROP_RE.search(line) or PARAM_RE.search(line)): return

        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Delete Line", command=lambda: self._add_line_deletion_edit(ln))
        menu.post(event.x_root, event.y_root)

    def _add_line_deletion_edit(self, ln: int):
        if not self.current_file: return
            
        line = self.txt.get(f"{ln + 1}.0", f"{ln + 1}.end")
        pname, oval = "", ""
        if m := PROP_RE.search(line): pname, oval = m.groups()
        elif m := PARAM_RE.search(line): pname, oval = m.groups()
        else: return

        context = self._find_context_name(ln)
        edit = ModEdit(
            file_path=str(self.current_file), line_number=ln,
            original_value=oval.strip(),
            current_value=line.strip(),
            description=context or Path(self.current_file).stem,
            param_name=pname, edit_type='LINE_DELETE'
        )
        self.active_edits[edit.key()] = edit
        self._refresh_edits_list()
    
    def _show_edit_in_preview(self, edit: ModEdit):
        if not edit: return
        file_path = Path(edit.file_path)
        def highlight():
            self.txt.tag_remove("highlight", "1.0", tk.END)
            start, end = f"{edit.line_number + 1}.0", f"{edit.end_line_number + 1}.end"
            self.txt.see(start); self.txt.tag_add("highlight", start, end)

        if self.current_file != file_path:
            item_id = self.path_to_id.get(file_path)
            if item_id and self.tree.exists(item_id):
                self.tree.selection_set(item_id); self.tree.focus(item_id); self.tree.see(item_id)
                self.after(50, highlight)
            else: self._on_tree_select_path(file_path); self.after(50, highlight)
        else: highlight()

    def _find_params(self) -> None:
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load a game data .pak first."); return
        if not (query := self.ent_search.get().strip().lower()): messagebox.showinfo(APP_NAME, "Please enter search terms."); return
        kws = query.split()
        self.lst_results.delete(0, tk.END); self.search_results.clear()
        if not (scr_files := [p for p in self.path_to_id if p.name.endswith(".scr")]): self._set_status("No .scr files."); return
        self._show_progress("Searching...")
        threading.Thread(target=self._run_search_in_background, args=(scr_files, kws)).start()

    def _run_search_in_background(self, scr_files: List[Path], kws: List[str]):
        scan_func = partial(scan_scr_for_hits, kws=kws)
        results = []
        # For I/O-bound tasks like reading many small files, ThreadPoolExecutor can be faster
        # due to lower overhead than ProcessPoolExecutor, especially on Windows.
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for future in concurrent.futures.as_completed([executor.submit(scan_func, f) for f in scr_files]):
                    results.extend(future.result())
        except Exception: 
            results = [item for f in scr_files for item in scan_func(f)]
        finally: 
            self.after(0, self._finish_search, results)

    def _finish_search(self, results: List[ModEdit]):
        self._hide_progress()
        self.search_results = sorted(list({ed.key(): ed for ed in results}.values()), key=lambda e: (e.edit_type, Path(e.file_path).name.lower(), e.line_number))
        for ed in self.search_results:
            label = f'[BLOCK] {ed.description}' if ed.edit_type == 'BLOCK_DELETE' else f"{ed.description} -> {ed.param_name}"
            self.lst_results.insert(tk.END, label)
        self._set_status(f"Found {len(self.search_results)} match(es).")

    def _on_result_select(self, _evt=None) -> None:
        if sel := self.lst_results.curselection(): self._show_edit_in_preview(self.search_results[sel[0]])
        
    def _on_add_from_result(self, _evt=None) -> None:
        if not (sel := self.lst_results.curselection()): return
        ed = self.search_results[sel[0]]
        if ed.edit_type == 'BLOCK_DELETE':
            if messagebox.askyesno("Confirm Deletion", f"Mark this block for deletion?\n\n{ed.description}"):
                self.active_edits[ed.key()] = ed; self._refresh_edits_list()
            return

        default_val = ed.current_value
        if default_val.startswith('"') and default_val.endswith('"') and ',' not in default_val:
            default_val = default_val[1:-1]
        
        initial_desc = ed.param_name if ed.is_param else ed.description
        dialog = EditDialog(self, "Add to Mod", ed.param_name, initial_desc, default_val)
        if dialog.result is None: return
        
        new_desc, new_val_str = dialog.result
        final_val = new_val_str
        if ed.original_value.startswith('"') and not (new_val_str.startswith('"') and new_val_str.endswith('"')) and ',' not in new_val_str:
            final_val = f'"{new_val_str}"'
        
        ed.current_value = final_val
        ed.description = new_desc
        self.active_edits[ed.key()] = ed
        self._refresh_edits_list()

    def _refresh_edits_list(self) -> None:
        self.lst_edits.delete(0, tk.END)
        for ed in sorted(self.active_edits.values(), key=lambda e:(e.edit_type, e.description.lower(), e.param_name.lower())):
            chk = "☑" if ed.is_enabled else "☐"
            if ed.edit_type == 'BLOCK_DELETE': shown = f'{chk} [DELETE BLOCK] {ed.description}'
            elif ed.edit_type == 'LINE_DELETE': shown = f'{chk} [DELETE LINE] {ed.description}: {ed.current_value}'
            else: shown = f"{chk}  {ed.description}: {ed.param_name} = {ed.current_value}  (was {ed.original_value})"
            self.lst_edits.insert(tk.END, shown)

    def _selected_edit(self) -> Optional[ModEdit]:
        if not (sel := self.lst_edits.curselection()): return None
        ordered = sorted(self.active_edits.values(), key=lambda e:(e.edit_type, e.description.lower(), e.param_name.lower()))
        try: return ordered[sel[0]]
        except IndexError: return None

    def _on_edit_select(self, _evt=None):
        if edit := self._selected_edit(): self._show_edit_in_preview(edit)
    def _toggle_selected_edit(self):
        if ed := self._selected_edit(): ed.is_enabled = not ed.is_enabled; self._refresh_edits_list()
    def _delete_selected_edit(self):
        if ed := self._selected_edit(): del self.active_edits[ed.key()]; self._refresh_edits_list()
    def _clear_edits(self):
        if self.active_edits and messagebox.askyesno(APP_NAME, "Clear all edits?"):
            self.active_edits.clear(); self._refresh_edits_list()

    def _change_edit_to_delete_line(self):
        if ed := self._selected_edit():
            try:
                p = Path(ed.file_path)
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                if ed.line_number < len(lines):
                    ed.current_value = lines[ed.line_number].strip()
                else: ed.current_value = f"{ed.param_name}({ed.original_value});"
            except Exception: ed.current_value = f"{ed.param_name}({ed.original_value});"
            ed.edit_type = 'LINE_DELETE'; self._refresh_edits_list()
    
    def _revert_delete_to_edit(self):
        if ed := self._selected_edit():
            ed.edit_type = 'VALUE_REPLACE'
            ed.current_value = ed.original_value
            self._refresh_edits_list()

    def _edits_context(self, event) -> None:
        self.lst_edits.selection_clear(0, tk.END); self.lst_edits.selection_set(idx := self.lst_edits.nearest(event.y)); self.lst_edits.activate(idx)
        if not self.lst_edits.curselection() or not (edit := self._selected_edit()): return
        
        menu = tk.Menu(self, tearoff=0)
        if edit.edit_type == 'VALUE_REPLACE':
            menu.add_command(label="Edit Value & Description", command=self._edit_selected_value)
            menu.add_command(label="Delete Line", command=self._change_edit_to_delete_line)
            menu.add_separator()
        elif edit.edit_type == 'LINE_DELETE':
             menu.add_command(label="Revert to Value Edit", command=self._revert_delete_to_edit)
             menu.add_separator()
        
        menu.add_command(label="Toggle Enable", command=self._toggle_selected_edit)
        menu.add_command(label="Delete", command=self._delete_selected_edit)
        menu.post(event.x_root, event.y_root)

    def _edit_selected_value(self) -> None:
        if not (ed := self._selected_edit()) or ed.edit_type != 'VALUE_REPLACE': return
        
        initial_val = ed.current_value
        if initial_val.startswith('"') and initial_val.endswith('"') and ',' not in initial_val: initial_val = initial_val[1:-1]
        
        initial_desc = ed.description if not ed.is_param else ed.param_name
        dialog = EditDialog(self, "Edit Property", ed.param_name, initial_desc, initial_val)
        if dialog.result is None: return

        new_desc, new_val_str = dialog.result
        final_val = new_val_str
        if ed.original_value.startswith('"') and not (new_val_str.startswith('"') and new_val_str.endswith('"')) and ',' not in new_val_str:
             final_val = f'"{new_val_str}"'
        
        ed.current_value = final_val
        ed.description = new_desc
        self._refresh_edits_list()

    def _save_project(self) -> None:
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load game data first."); return
        if not (p := filedialog.asksaveasfilename(initialdir=self.settings.last_project_dir, defaultextension=".dl3mod", filetypes=[("DL3 Mod Project","*.dl3mod")])): return
        self.settings.last_project_dir = str(Path(p).parent); self.settings.save()
        payload = {"edits": [{**ed.__dict__, "file_path": str(Path(ed.file_path).relative_to(self.temp_root))} for ed in self.active_edits.values()]}
        write_json(Path(p), payload); messagebox.showinfo(APP_NAME, "Project saved.")

    def _load_project(self) -> None:
        if not (p := filedialog.askopenfilename(initialdir=self.settings.last_project_dir, filetypes=[("DL3 Mod Project","*.dl3mod")])): return
        self.settings.last_project_dir = str(Path(p).parent); self.settings.save()
        data = read_json(Path(p), None)
        if not data or "edits" not in data: messagebox.showerror(APP_NAME, "Invalid project file."); return
        if not self.temp_root: messagebox.showwarning(APP_NAME, "Load game data first, then the project."); return
        self.active_edits.clear()
        for d in data["edits"]:
            d.setdefault('is_param', False)
            me = ModEdit(file_path=str(self.temp_root / d["file_path"]), **{k:v for k,v in d.items() if k != "file_path"})
            self.active_edits[me.key()] = me
        self._refresh_edits_list(); messagebox.showinfo(APP_NAME, "Project loaded.")

    def _pack_pak(self) -> None:
        if not self.active_edits: messagebox.showwarning(APP_NAME, "No active edits to pack."); return
        if not (out := filedialog.asksaveasfilename(defaultextension=".pak", filetypes=[("PAK files","*.pak")])): return
        
        edits_by_file: Dict[str, List[ModEdit]] = {}
        for ed in self.active_edits.values():
            if ed.is_enabled: edits_by_file.setdefault(ed.file_path, []).append(ed)
        try:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
                for fpath, edits in edits_by_file.items():
                    p = Path(fpath)
                    lines_to_delete, value_edits = set(), []
                    for edit in edits:
                        if edit.edit_type == 'BLOCK_DELETE': lines_to_delete.update(range(edit.line_number, edit.end_line_number + 1))
                        elif edit.edit_type == 'LINE_DELETE': lines_to_delete.add(edit.line_number)
                        else: value_edits.append(edit)
                    
                    modified_lines = p.read_text(encoding="utf-8", errors="ignore").splitlines(True)
                    for e in sorted(value_edits, key=lambda x: x.line_number):
                        if e.line_number >= len(modified_lines): continue
                        orig = modified_lines[e.line_number]
                        if (m := PARAM_RE.search(orig)) and e.param_name == m.group(1):
                            before, after = f'Param("{e.param_name}", {e.original_value})', f'Param("{e.param_name}", {e.current_value})'
                            modified_lines[e.line_number] = orig.replace(before, after, 1)
                        elif (pm := PROP_RE.search(orig)) and pm.group(1) == e.param_name:
                            start, end = orig.find("("), orig.rfind(")")
                            if -1 < start < end: modified_lines[e.line_number] = f"{orig[:start+1]}{e.current_value}{orig[end:]}"
                        else: modified_lines[e.line_number] = orig.replace(e.original_value, e.current_value, 1)
                    
                    final_content = "".join([line for i, line in enumerate(modified_lines) if i not in lines_to_delete])
                    rel = str(p.relative_to(self.temp_root)) if self.temp_root else p.name
                    zf.writestr(rel.replace(os.sep, "/"), final_content.encode("utf-8"))
            messagebox.showinfo(APP_NAME, f"Packed mod: {out}")
        except Exception as e: messagebox.showerror(APP_NAME, f"Failed to pack: {e}")

    def _open_settings(self) -> None:
        win = tk.Toplevel(self); win.title("General Settings"); win.transient(self)
        frm = ttk.Frame(win, padding=8); frm.pack(fill=tk.BOTH, expand=True)
        v_last = tk.StringVar(value=self.settings.last_pak_dir); v_dark = tk.BooleanVar(value=self.settings.dark_mode)
        r = ttk.Frame(frm); r.pack(fill=tk.X, pady=4)
        ttk.Label(r, text="Default Folder:", width=14).pack(side=tk.LEFT)
        ttk.Entry(r, textvariable=v_last).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(r, text="Browse…", command=lambda: self._pick_dir(v_last)).pack(side=tk.LEFT)
        ttk.Checkbutton(frm, text="Dark mode (restart required)", variable=v_dark).pack(anchor="w", pady=(6,0))
        ttk.Button(frm, text="Save", command=lambda: self._save_general_settings(win, v_last, v_dark)).pack(anchor="e", pady=(10,0))

    def _open_color_settings(self) -> None:
        win = tk.Toplevel(self); win.title("Color Settings"); win.transient(self); win.resizable(False, False)
        frm = ttk.Frame(win, padding=15); frm.pack(fill=tk.BOTH, expand=True)
        mode = "dark" if self.settings.dark_mode else "light"
        ttk.Label(frm, text="Click to change color for the current theme.").pack(anchor="w", pady=(0, 10))
        color_vars = {k: tk.StringVar(value=v) for k, v in self.settings.colors[mode].items()}

        def create_picker(key, label_text):
            row = ttk.Frame(frm); row.pack(fill=tk.X, pady=5)
            ttk.Label(row, text=label_text, width=15).pack(side=tk.LEFT)
            btn = tk.Button(row, text="Pick Color", width=10, relief=tk.GROOVE, bg=color_vars[key].get())
            btn.pack(side=tk.LEFT, padx=5)
            def pick_color():
                if (color := askcolor(color_vars[key].get(), title=f"Select color for {label_text}")) and color[1]:
                    color_vars[key].set(color[1]); btn.config(bg=color[1])
            btn.config(command=pick_color)
        create_picker("param", "Params:"); create_picker("prop", "Properties:"); create_picker("block_header", "Block Headers:")

        def save_colors():
            for key, var in color_vars.items(): self.settings.colors[mode][key] = var.get()
            self.settings.save(); self._configure_text_tags()
            if self.current_file: self._apply_syntax_highlighting()
            win.destroy()
        ttk.Button(frm, text="Save & Close", command=save_colors).pack(anchor="e", pady=(20,0))

    def _pick_dir(self, var: tk.StringVar) -> None:
        if p := filedialog.askdirectory(): var.set(p)

    def _save_general_settings(self, win: tk.Toplevel, v_last: tk.StringVar, v_dark: tk.BooleanVar) -> None:
        self.settings.last_pak_dir = v_last.get().strip() or self.settings.last_pak_dir
        self.settings.dark_mode = v_dark.get(); self.settings.save(); win.destroy()

    def _on_close(self) -> None:
        if self.active_edits and not messagebox.askyesno("Quit", "You have unsaved edits. Are you sure you want to quit?"): return
        self._cleanup_temp(); self.destroy()

def main() -> None:
    # This check is necessary for multiprocessing to work correctly when frozen with PyInstaller on Windows.
    if sys.platform.startswith('win'):
        import multiprocessing
        multiprocessing.freeze_support()
    App().mainloop()

if __name__ == "__main__":
    main()

