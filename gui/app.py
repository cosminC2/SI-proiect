from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .file_ops import decrypt_file_bytes, encrypt_file_bytes, validate_input_file
from .message_ops import decrypt_message_bytes, encrypt_message_bytes
from .test_vectors_runner import run_all_vectors
from .utils import generate_random_key_hex, parse_hex_key


class EncryptionApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AES-GCM Encrypt/Decrypt")
        self.geometry("760x540")
        self.minsize(700, 500)

        self.file_in_var = tk.StringVar()
        self.file_out_var = tk.StringVar()

        self._build_ui()

    def _build_ui(self) -> None:
        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="AES Key (hex):").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(main)
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(main, text="Generate 256-bit Key", command=self.generate_key).grid(row=0, column=2, sticky="ew")

        ttk.Label(main, text="AAD (optional):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.aad_entry = ttk.Entry(main)
        self.aad_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=8, pady=(8, 0))

        tabs = ttk.Notebook(main)
        tabs.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(12, 0))

        msg_tab = ttk.Frame(tabs, padding=10)
        file_tab = ttk.Frame(tabs, padding=10)
        tests_tab = ttk.Frame(tabs, padding=10)
        tabs.add(msg_tab, text="Message")
        tabs.add(file_tab, text="File")
        tabs.add(tests_tab, text="Test Vectors")

        self._build_message_tab(msg_tab)
        self._build_file_tab(file_tab)
        self._build_tests_tab(tests_tab)

        main.columnconfigure(1, weight=1)
        main.rowconfigure(2, weight=1)

    def _build_message_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Input:").grid(row=0, column=0, sticky="w")
        self.input_text = tk.Text(parent, height=8, wrap="word")
        self.input_text.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(4, 8))

        btns = ttk.Frame(parent)
        btns.grid(row=2, column=0, columnspan=3, sticky="w")
        ttk.Button(btns, text="Encrypt Message", command=self.encrypt_message).pack(side="left")
        ttk.Button(btns, text="Decrypt Message", command=self.decrypt_message).pack(side="left", padx=8)

        ttk.Label(parent, text="Output:").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.output_text = tk.Text(parent, height=8, wrap="word")
        self.output_text.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(4, 0))

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        parent.rowconfigure(4, weight=1)

    def _build_file_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Input file:").grid(row=0, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.file_in_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(parent, text="Browse", command=self.pick_input_file).grid(row=0, column=2, sticky="ew")

        ttk.Label(parent, text="Output file:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(parent, textvariable=self.file_out_var).grid(row=1, column=1, sticky="ew", padx=8, pady=(8, 0))
        ttk.Button(parent, text="Save As", command=self.pick_output_file).grid(row=1, column=2, sticky="ew", pady=(8, 0))

        btns = ttk.Frame(parent)
        btns.grid(row=2, column=0, columnspan=3, sticky="w", pady=(14, 0))
        ttk.Button(btns, text="Encrypt File", command=self.encrypt_file).pack(side="left")
        ttk.Button(btns, text="Decrypt File", command=self.decrypt_file).pack(side="left", padx=8)

        parent.columnconfigure(1, weight=1)

    def _build_tests_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Button(top, text="Run All Test Vectors", command=self.run_all_test_vectors).pack(side="left")
        self.tests_summary_var = tk.StringVar(value="No tests run yet.")
        ttk.Label(top, textvariable=self.tests_summary_var).pack(side="left", padx=12)

        columns = ("suite", "index", "operation", "expected", "got", "tag_expected", "tag_got", "status")
        self.tests_tree = ttk.Treeview(parent, columns=columns, show="headings", height=16)
        for name, width in (
            ("suite", 100),
            ("index", 60),
            ("operation", 120),
            ("expected", 210),
            ("got", 210),
            ("tag_expected", 210),
            ("tag_got", 210),
            ("status", 80),
        ):
            self.tests_tree.heading(name, text=name.upper())
            self.tests_tree.column(name, width=width, anchor="w", stretch=True)

        y_scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tests_tree.yview)
        x_scroll = ttk.Scrollbar(parent, orient="horizontal", command=self.tests_tree.xview)
        self.tests_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tests_tree.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        y_scroll.grid(row=1, column=1, sticky="ns", pady=(10, 0))
        x_scroll.grid(row=2, column=0, sticky="ew")

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

    def get_key_and_aad(self) -> tuple[bytes, bytes]:
        key = parse_hex_key(self.key_entry.get())
        aad = self.aad_entry.get().encode("utf-8")
        return key, aad

    def generate_key(self) -> None:
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, generate_random_key_hex())

    def encrypt_message(self) -> None:
        try:
            key, aad = self.get_key_and_aad()
            plaintext = self.input_text.get("1.0", tk.END).rstrip("\n").encode("utf-8")
            packed = encrypt_message_bytes(key=key, aad=aad, plaintext=plaintext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", packed)
        except Exception as exc:
            messagebox.showerror("Encryption error", str(exc))

    def decrypt_message(self) -> None:
        try:
            key, aad = self.get_key_and_aad()
            payload = self.input_text.get("1.0", tk.END)
            plaintext = decrypt_message_bytes(key=key, aad=aad, payload_b64=payload)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", plaintext.decode("utf-8", errors="replace"))
        except Exception as exc:
            messagebox.showerror("Decryption error", str(exc))

    def pick_input_file(self) -> None:
        path = filedialog.askopenfilename(title="Select input file")
        if path:
            self.file_in_var.set(path)

    def pick_output_file(self) -> None:
        path = filedialog.asksaveasfilename(title="Select output file")
        if path:
            self.file_out_var.set(path)

    def ensure_output_path(self) -> Path | None:
        raw = self.file_out_var.get().strip()
        if not raw:
            self.pick_output_file()
            raw = self.file_out_var.get().strip()
            if not raw:
                return None

        try:
            candidate = Path(raw)
        except Exception:
            candidate = None

        invalid = (
            candidate is None
            or candidate.exists() and candidate.is_dir()
            or candidate.parent and not candidate.parent.exists()
        )
        if invalid:
            messagebox.showwarning("Invalid output path", "Please choose a valid output file path.")
            self.pick_output_file()
            raw = self.file_out_var.get().strip()
            if not raw:
                return None
            candidate = Path(raw)
            if candidate.exists() and candidate.is_dir():
                raise ValueError("Output path cannot be a directory.")
            if candidate.parent and not candidate.parent.exists():
                raise ValueError("Output directory does not exist.")
        return candidate

    def encrypt_file(self) -> None:
        try:
            key, aad = self.get_key_and_aad()
            src = validate_input_file(self.file_in_var.get())
            dst = self.ensure_output_path()
            if dst is None:
                return
            raw = encrypt_file_bytes(key=key, aad=aad, plaintext=src.read_bytes())
            dst.write_bytes(raw)
            messagebox.showinfo("Success", f"Encrypted file written to:\n{dst}")
        except Exception as exc:
            messagebox.showerror("Encryption error", str(exc))

    def decrypt_file(self) -> None:
        try:
            key, aad = self.get_key_and_aad()
            src = validate_input_file(self.file_in_var.get())
            dst = self.ensure_output_path()
            if dst is None:
                return
            plaintext = decrypt_file_bytes(key=key, aad=aad, raw=src.read_bytes())
            dst.write_bytes(plaintext)
            messagebox.showinfo("Success", f"Decrypted file written to:\n{dst}")
        except Exception as exc:
            messagebox.showerror("Decryption error", str(exc))

    def run_all_test_vectors(self) -> None:
        self.tests_tree.delete(*self.tests_tree.get_children())
        try:
            rows, passed, total = run_all_vectors()
            for row in rows:
                self.tests_tree.insert(
                    "",
                    "end",
                    values=(
                        row.suite,
                        row.index,
                        row.operation,
                        row.expected.hex(),
                        row.got.hex(),
                        row.tag_expected.hex(),
                        row.tag_got.hex(),
                        "OK" if row.ok else "ERR",
                    ),
                )
            self.tests_summary_var.set(f"Passed {passed}/{total} checks.")
        except Exception as exc:
            self.tests_summary_var.set("Test run failed.")
            messagebox.showerror("Test vector error", str(exc))

