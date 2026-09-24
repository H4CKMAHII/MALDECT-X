import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from analyzer.entropy_analyzer import calculate_entropy
from analyzer.file_identifier import identify_file
from analyzer.hash_analyzer import calculate_hashes
from analyzer.metadata_analyzer import get_metadata
from analyzer.pe_analyzer import analyze_pe
from analyzer.risk_engine import calculate_risk
from analyzer.string_analyzer import (
    extract_strings,
    find_suspicious_strings,
)
from analyzer.yara_analyzer import scan_with_yara

# =========================
# THEME
# =========================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG = "#050812"
PANEL = "#0A1020"
PANEL_2 = "#0D1428"
CYAN = "#00F5FF"
PURPLE = "#9D4EDD"
TEXT = "#E8F1FF"
MUTED = "#71809B"
GREEN = "#00FF9C"
RED = "#FF3864"
ORANGE = "#FFB000"


class MalDetectX(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("MalDetect-X | Malware Analysis")
        self.geometry("1150x760")
        self.minsize(1000, 700)

        self.configure(fg_color=BG)

        self.current_sha256 = ""

        self.build_header()
        self.build_file_panel()
        self.build_info_cards()
        self.build_analysis_panel()
        self.build_events_panel()

    # =========================
    # HEADER
    # =========================

    def build_header(self):

        header = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        header.pack(fill="x", padx=30, pady=(22, 0))

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")

        title = ctk.CTkLabel(
            title_frame,
            text="◈ MALDETECT-X",
            text_color=CYAN,
            font=("Arial", 27, "bold"),
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            title_frame,
            text="MALWARE ANALYSIS & THREAT DETECTION",
            text_color=MUTED,
            font=("Arial", 11, "bold"),
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        status = ctk.CTkLabel(
            header,
            text="● SYSTEM ONLINE",
            text_color=GREEN,
            font=("Arial", 12, "bold"),
        )
        status.pack(side="right", pady=10)

        line = ctk.CTkFrame(self, height=1, fg_color=CYAN)
        line.pack(fill="x", padx=30, pady=(15, 15))

    # =========================
    # FILE PANEL
    # =========================

    def build_file_panel(self):

        self.file_panel = ctk.CTkFrame(
            self,
            fg_color=PANEL,
            border_width=1,
            border_color=CYAN,
            corner_radius=12,
        )
        self.file_panel.pack(fill="x", padx=30, pady=5)

        label = ctk.CTkLabel(
            self.file_panel,
            text="DROP FILE / SELECT FILE",
            text_color=TEXT,
            font=("Arial", 15, "bold"),
        )
        label.pack(pady=(18, 5))

        self.file_name = ctk.CTkLabel(
            self.file_panel,
            text="⬆  DROP ANY FILE HERE",
            text_color=CYAN,
            font=("Arial", 18, "bold"),
        )
        self.file_name.pack(pady=12)

        self.analyze_button = ctk.CTkButton(
            self.file_panel,
            text="ANALYZE FILE",
            width=190,
            height=38,
            fg_color=PURPLE,
            hover_color="#7B2CBF",
            text_color="white",
            font=("Arial", 13, "bold"),
            command=self.select_file,
        )
        self.analyze_button.pack(pady=(2, 18))

    # =========================
    # INFO CARDS
    # =========================

    def build_info_cards(self):

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=30, pady=15)

        self.type_card = self.create_card(container, "FILE TYPE", "—")
        self.hash_card = self.create_card(container, "SHA-256", "—")
        self.entropy_card = self.create_card(container, "ENTROPY", "—")
        self.risk_card = self.create_card(container, "RISK", "—")

    def create_card(self, parent, title, value):

        card = ctk.CTkFrame(
            parent,
            fg_color=PANEL_2,
            border_width=1,
            border_color="#182640",
            corner_radius=10,
        )

        card.pack(side="left", fill="both", expand=True, padx=5)

        title_label = ctk.CTkLabel(
            card, text=title, text_color=MUTED, font=("Arial", 10, "bold")
        )

        title_label.pack(pady=(10, 3))

        if title == "SHA-256":
            value_label = ctk.CTkEntry(
                card,
                width=230,
                height=30,
                fg_color="transparent",
                border_width=0,
                text_color=CYAN,
                justify="center",
                font=("Arial", 12, "bold"),
            )
            value_label.insert(0, value)
            value_label.configure(state="readonly")
            value_label.bind("<Button-1>", lambda event: self.copy_hash(event))
        else:
            value_label = ctk.CTkLabel(
                card, text=value, text_color=CYAN, font=("Arial", 16, "bold")
            )

        value_label.pack(pady=(0, 12), padx=8)

        return value_label

    def copy_hash(self, event):
        if self.current_sha256 and self.current_sha256 != "—":
            self.clipboard_clear()
            self.clipboard_append(self.current_sha256)
            messagebox.showinfo(
                "Clipboard", "SHA-256 hash copied to clipboard!"
            )

    # =========================
    # ANALYSIS PANEL
    # =========================

    def build_analysis_panel(self):

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=30)

        # LEFT
        left = ctk.CTkFrame(
            container,
            fg_color=PANEL,
            border_width=1,
            border_color=PURPLE,
            corner_radius=10,
        )
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))

        ctk.CTkLabel(
            left,
            text="STATIC ANALYSIS",
            text_color=PURPLE,
            font=("Arial", 14, "bold"),
        ).pack(anchor="w", padx=20, pady=(15, 10))

        self.hash_status = self.analysis_item(left, "Hash Analysis")
        self.string_status = self.analysis_item(left, "String Analysis")
        self.entropy_status = self.analysis_item(left, "Entropy Analysis")
        self.pe_status = self.analysis_item(left, "PE Analysis")
        self.yara_status = self.analysis_item(left, "YARA Analysis")

        # RIGHT
        right = ctk.CTkFrame(
            container,
            fg_color=PANEL,
            border_width=1,
            border_color=CYAN,
            corner_radius=10,
        )
        right.pack(side="right", fill="both", expand=True, padx=(7, 0))

        ctk.CTkLabel(
            right,
            text="THREAT ASSESSMENT",
            text_color=CYAN,
            font=("Arial", 14, "bold"),
        ).pack(anchor="w", padx=20, pady=(15, 5))

        self.score_label = ctk.CTkLabel(
            right, text="◉  — / 100", text_color=CYAN, font=("Arial", 30, "bold")
        )
        self.score_label.pack(pady=(8, 0))

        self.verdict_label = ctk.CTkLabel(
            right,
            text="WAITING FOR SCAN",
            text_color=MUTED,
            font=("Arial", 15, "bold"),
        )
        self.verdict_label.pack(pady=5)

        self.progress = ctk.CTkProgressBar(
            right,
            width=350,
            height=12,
            progress_color=CYAN,
            fg_color="#182033",
        )
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.reasons_box = ctk.CTkTextbox(
            right,
            height=100,
            fg_color="#070C18",
            border_width=0,
            text_color=TEXT,
            font=("Courier New", 11),
        )
        self.reasons_box.pack(fill="x", padx=20, pady=(3, 15))

    def analysis_item(self, parent, text):

        label = ctk.CTkLabel(
            parent, text=f"✓  {text}", text_color=MUTED, font=("Arial", 12)
        )
        label.pack(anchor="w", padx=20, pady=5)

        return label

    # =========================
    # EVENTS
    # =========================

    def build_events_panel(self):

        panel = ctk.CTkFrame(
            self,
            fg_color=PANEL,
            border_width=1,
            border_color="#182640",
            corner_radius=10,
        )
        panel.pack(fill="both", expand=True, padx=30, pady=(15, 25))

        ctk.CTkLabel(
            panel,
            text="DETECTION EVENTS",
            text_color=CYAN,
            font=("Arial", 13, "bold"),
        ).pack(anchor="w", padx=20, pady=(12, 5))

        self.events_box = ctk.CTkTextbox(
            panel,
            fg_color="#070C18",
            text_color=TEXT,
            border_width=0,
            font=("Courier New", 11),
        )
        self.events_box.pack(
            fill="both", expand=True, padx=15, pady=(0, 12)
        )

        self.events_box.insert("end", "[SYSTEM] MalDetect-X engine initialized.\n")
        self.events_box.insert("end", "[SYSTEM] Waiting for file analysis...\n")

    # =========================
    # FILE SELECTION
    # =========================

    def select_file(self):

        file_path = filedialog.askopenfilename(title="Select File")

        if not file_path:
            return

        self.file_name.configure(
            text=file_path.split("/")[-1], text_color=TEXT
        )

        self.events_box.delete("1.0", "end")
        self.events_box.insert("end", "[SCAN] File selected.\n")

        # Run scan in a background thread to prevent UI freezing
        threading.Thread(
            target=self.scan_file, args=(file_path,), daemon=True
        ).start()

    # =========================
    # SCAN
    # =========================

    def scan_file(self, file_path):

        try:
            self.analyze_button.configure(
                text="ANALYZING...", state="disabled"
            )

            metadata = get_metadata(file_path)
            file_info = identify_file(file_path)
            hashes = calculate_hashes(file_path)

            strings = extract_strings(file_path)
            suspicious = find_suspicious_strings(strings)

            entropy = calculate_entropy(file_path)

            pe_info = analyze_pe(file_path)

            yara_matches = scan_with_yara(
                file_path, "rules/malware_rules.yar"
            )

            risk = calculate_risk(
                suspicious_strings=len(suspicious),
                suspicious_imports=len(pe_info.get("suspicious_imports", [])),
                yara_matches=len(yara_matches),
                entropy=entropy,
            )

            # Safely schedule UI updates on main thread
            self.after(
                0,
                self.update_dashboard,
                metadata,
                file_info,
                hashes,
                strings,
                suspicious,
                entropy,
                pe_info,
                yara_matches,
                risk,
            )

        except Exception as error:
            self.after(
                0, messagebox.showerror, "Analysis Error", str(error)
            )

        finally:
            self.after(
                0,
                self.analyze_button.configure,
                {"text": "ANALYZE FILE", "state": "normal"},
            )

    # =========================
    # UPDATE DASHBOARD
    # =========================

    def update_dashboard(
        self,
        metadata,
        file_info,
        hashes,
        strings,
        suspicious,
        entropy,
        pe_info,
        yara_matches,
        risk,
    ):

        # Cards
        self.type_card.configure(text=file_info.get("type", "Unknown"))

        sha256 = hashes.get("sha256", "—")
        self.current_sha256 = sha256

        if sha256 != "—":
            self.hash_card.configure(state="normal")
            self.hash_card.delete(0, "end")
            self.hash_card.insert(0, sha256[:12] + "...")
            self.hash_card.configure(state="readonly")
        else:
            self.hash_card.configure(state="normal")
            self.hash_card.delete(0, "end")
            self.hash_card.insert(0, "—")
            self.hash_card.configure(state="readonly")

        self.entropy_card.configure(text=str(round(entropy, 2)))
        self.risk_card.configure(text=f"{risk['score']}/100")

        # Static analysis
        self.hash_status.configure(text="✓  Hash Analysis", text_color=GREEN)

        self.string_status.configure(
            text=f"✓  String Analysis ({len(suspicious)} suspicious)",
            text_color=GREEN if not suspicious else ORANGE,
        )

        self.entropy_status.configure(
            text=f"✓  Entropy Analysis ({round(entropy, 2)})",
            text_color=GREEN if entropy < 7.2 else ORANGE,
        )

        if pe_info.get("is_pe"):
            self.pe_status.configure(text="✓  PE Analysis", text_color=GREEN)
        else:
            self.pe_status.configure(
                text="—  PE Analysis (N/A)", text_color=MUTED
            )

        self.yara_status.configure(
            text=f"✓  YARA Analysis ({len(yara_matches)} matches)",
            text_color=GREEN if not yara_matches else RED,
        )

        # Risk
        score = risk["score"]
        verdict = risk["verdict"]

        self.score_label.configure(text=f"◉  {score} / 100")
        self.progress.set(score / 100)

        if verdict == "CRITICAL":
            color = RED
        elif verdict == "HIGH RISK":
            color = ORANGE
        elif verdict == "SUSPICIOUS":
            color = "#FFD000"
        else:
            color = GREEN

        self.risk_card.configure(text_color=color)
        self.score_label.configure(text_color=color)
        self.verdict_label.configure(text=verdict, text_color=color)
        self.progress.configure(progress_color=color)

        # Reasons
        self.reasons_box.delete("1.0", "end")
        if risk.get("reasons"):
            for reason in risk["reasons"]:
                self.reasons_box.insert("end", f"[!] {reason}\n")
        else:
            self.reasons_box.insert(
                "end", "[✓] No significant indicators detected.\n"
            )

        # Events
        self.events_box.delete("1.0", "end")
        self.events_box.insert("end", "[SCAN] Analysis completed.\n")
        self.events_box.insert(
            "end", f"[INFO] File type: {file_info.get('type')}\n"
        )
        self.events_box.insert(
            "end", f"[INFO] Entropy: {round(entropy, 2)}\n"
        )

        for finding in suspicious[:10]:
            self.events_box.insert(
                "end", f"[!] Suspicious string: {finding['keyword']}\n"
            )

        for api in pe_info.get("suspicious_imports", []):
            self.events_box.insert("end", f"[!] Suspicious API: {api}\n")

        for match in yara_matches:
            self.events_box.insert(
                "end", f"[!] YARA rule matched: {match['rule']}\n"
            )

        self.events_box.insert(
            "end", f"[RISK] Final verdict: {verdict} ({score}/100)\n"
        )


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":
    app = MalDetectX()
    app.mainloop()
