

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests

from crypto_engine import (
    generate_dh_keypair, compute_shared_secret,
    derive_aes_key, encrypt_file, decrypt_file,
    save_private_key, load_private_key, has_local_keys
)

SERVER  = "http://localhost:5000"
KEY_DIR = os.path.join(os.path.expanduser("~"), ".secureshare", "keys")
DL_DIR  = os.path.join(os.path.expanduser("~"), "Downloads", "SecureShare")

BG     = "#1e1e2e"
BG2    = "#2a2a3e"
ACCENT = "#7c6af7"
TEXT   = "#cdd6f4"
TEXT2  = "#6c7086"
GREEN  = "#a6e3a1"
RED    = "#f38ba8"
YELLOW = "#f9e2af"

def api_register(username, password, public_key):
    r = requests.post(f"{SERVER}/register", json={
        "username": username, "password": password,
        "dh_public_key": str(public_key)
    })
    if not r.ok:
        raise Exception(r.json().get("error", "Register failed"))
    return r.json()["token"]

def api_login(username, password):
    r = requests.post(f"{SERVER}/login", json={
        "username": username, "password": password
    })
    if not r.ok:
        raise Exception(r.json().get("error", "Login failed"))
    return r.json()["token"]

def api_get_users(token):
    r = requests.get(f"{SERVER}/users", headers={"X-Auth-Token": token})
    return r.json().get("users", [])

def api_get_pubkey(token, username):
    r = requests.get(f"{SERVER}/users/{username}/pubkey", headers={"X-Auth-Token": token})
    return int(r.json()["dh_public_key"])

def api_upload(token, encrypted_bytes, filename, recipient, sender_pub):
    r = requests.post(f"{SERVER}/upload",
        headers={"X-Auth-Token": token},
        data={"recipient": recipient, "original_filename": filename,
              "sender_dh_public_key": str(sender_pub)},
        files={"encrypted_file": (filename, encrypted_bytes)}
    )
    if not r.ok:
        raise Exception(r.json().get("error", "Upload failed"))
    return r.json()["file_id"]

def api_inbox(token):
    r = requests.get(f"{SERVER}/files/inbox", headers={"X-Auth-Token": token})
    return r.json().get("files", [])

def api_download(token, file_id):
    r = requests.get(f"{SERVER}/files/{file_id}", headers={"X-Auth-Token": token})
    return r.content

class App:
    def __init__(self, root):
        self.root        = root
        self.token       = None
        self.username    = None
        self.private_key = None
        self.public_key  = None

        self.root.title("SecureShare")
        self.root.geometry("700x500")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)
        self._show_login()

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _btn(self, parent, text, cmd, color=None):

        return tk.Button(parent, text=text, command=cmd,
                         bg=color or ACCENT, fg="white",
                         font=("Segoe UI", 10, "bold"),
                         relief="flat", bd=0, padx=16, pady=8, cursor="hand2")

    def _log(self, box, msg, color=TEXT):

        box.config(state="normal")
        box.insert("end", msg + "\n")
        box.tag_add(color, f"end-{len(msg)+2}c", "end-1c")
        box.tag_config(color, foreground=color)
        box.see("end")
        box.config(state="disabled")

    def _show_login(self):
        self._clear()
        self.root.title("SecureShare")

        tk.Label(self.root, text="🔐  SecureShare",
                 bg=BG, fg=ACCENT, font=("Segoe UI", 20, "bold")).pack(pady=(40, 4))
        tk.Label(self.root, text="End-to-End Encrypted File Sharing ",
                 bg=BG, fg=TEXT2, font=("Segoe UI", 10)).pack(pady=(0, 30))

        card = tk.Frame(self.root, bg=BG2, padx=30, pady=24)
        card.pack(padx=80, fill="x")

        self.tab = tk.StringVar(value="login")
        tab_row  = tk.Frame(card, bg=BG2)
        tab_row.pack(fill="x", pady=(0, 16))
        self.btn_login_tab = tk.Button(tab_row, text="Sign In",
            bg=ACCENT, fg="white", relief="flat",
            font=("Segoe UI", 10, "bold"), padx=20, pady=6,
            command=lambda: self._switch("login"))
        self.btn_login_tab.pack(side="left")
        self.btn_reg_tab = tk.Button(tab_row, text="Register",
            bg=BG2, fg=TEXT2, relief="flat",
            font=("Segoe UI", 10, "bold"), padx=20, pady=6,
            command=lambda: self._switch("register"))
        self.btn_reg_tab.pack(side="left", padx=(8, 0))

        tk.Label(card, text="Username", bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        self.e_user = tk.Entry(card, bg=BG, fg=TEXT, insertbackground=TEXT,
                               relief="flat", font=("Segoe UI", 11), bd=6)
        self.e_user.pack(fill="x", pady=(2, 10))

        tk.Label(card, text="Password", bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        self.e_pass = tk.Entry(card, bg=BG, fg=TEXT, insertbackground=TEXT,
                               relief="flat", font=("Segoe UI", 11), bd=6, show="•")
        self.e_pass.pack(fill="x", pady=(2, 10))

        self.confirm_frame = tk.Frame(card, bg=BG2)
        self.confirm_frame.pack(fill="x")
        tk.Label(self.confirm_frame, text="Confirm Password",
                 bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        self.e_pass2 = tk.Entry(self.confirm_frame, bg=BG, fg=TEXT, insertbackground=TEXT,
                                relief="flat", font=("Segoe UI", 11), bd=6, show="•")
        self.e_pass2.pack(fill="x", pady=(2, 10))
        self.confirm_frame.pack_forget()

        self.status_var = tk.StringVar()
        tk.Label(card, textvariable=self.status_var,
                 bg=BG2, fg=RED, font=("Segoe UI", 9), wraplength=400).pack(pady=(4, 0))

        self.submit_btn = self._btn(card, "→  Sign In", self._submit)
        self.submit_btn.pack(fill="x", pady=(12, 0))
        self.e_user.focus_set()

    def _switch(self, tab):
        """Switch between Sign In and Register tabs."""
        self.tab.set(tab)
        self.status_var.set("")
        if tab == "login":
            self.btn_login_tab.config(bg=ACCENT, fg="white")
            self.btn_reg_tab.config(bg=BG2, fg=TEXT2)
            self.confirm_frame.pack_forget()
            self.submit_btn.config(text="→  Sign In")
        else:
            self.btn_login_tab.config(bg=BG2, fg=TEXT2)
            self.btn_reg_tab.config(bg=ACCENT, fg="white")
            self.confirm_frame.pack(fill="x", before=self.submit_btn)
            self.submit_btn.config(text="🔑  Register")

    def _submit(self):
        username = self.e_user.get().strip().lower()
        password = self.e_pass.get().strip()
        pass2    = self.e_pass2.get().strip()
        tab      = self.tab.get()

        if not username or not password:
            self.status_var.set("Username and password are required.")
            return
        if tab == "register" and password != pass2:
            self.status_var.set("Passwords do not match.")
            return
        if tab == "register" and len(password) < 6:
            self.status_var.set("Password must be at least 6 characters.")
            return

        self.submit_btn.config(state="disabled", text="Please wait...")

        def run():
            try:
                if tab == "register":
                    priv, pub = generate_dh_keypair()
                    token = api_register(username, password, pub)
                    save_private_key(priv, pub, username, password, KEY_DIR)
                else:
                    token = api_login(username, password)
                    if not has_local_keys(username, KEY_DIR):
                        raise Exception("No local keys found. Please register first.")
                    priv, pub = load_private_key(username, password, KEY_DIR)

                self.root.after(0, lambda p=priv, q=pub, t=token:
                                self._on_login(username, p, q, t))
            except Exception as e:
                self.root.after(0, lambda msg=str(e): self._login_err(msg))

        threading.Thread(target=run, daemon=True).start()

    def _login_err(self, msg):
        self.status_var.set(msg)
        self.submit_btn.config(state="normal",
            text="→  Sign In" if self.tab.get() == "login" else "🔑  Register")

    def _on_login(self, username, priv, pub, token):
        self.username    = username
        self.private_key = priv
        self.public_key  = pub
        self.token       = token
        self._show_dashboard()

    def _show_dashboard(self):
        self._clear()
        self.root.title(f"SecureShare — {self.username}")

        hdr = tk.Frame(self.root, bg=BG2, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐 SecureShare", bg=BG2, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)
        tk.Label(hdr, text=f"● {self.username}", bg=BG2, fg=GREEN,
                 font=("Segoe UI", 10)).pack(side="right", padx=16)

        body = tk.Frame(self.root, bg=BG, padx=40, pady=30)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="What do you want to do?", bg=BG, fg=TEXT,
                 font=("Segoe UI", 13, "bold")).pack(pady=(0, 24))

        btn_frame = tk.Frame(body, bg=BG)
        btn_frame.pack()

        send_card = tk.Frame(btn_frame, bg=BG2, padx=30, pady=24, cursor="hand2")
        send_card.grid(row=0, column=0, padx=12)
        tk.Label(send_card, text="📤",                   bg=BG2, font=("Segoe UI", 28)).pack()
        tk.Label(send_card, text="Send File",            bg=BG2, fg=TEXT, font=("Segoe UI", 12, "bold")).pack()
        tk.Label(send_card, text="Encrypt & upload",     bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack()
        for w in [send_card] + send_card.winfo_children():
            w.bind("<Button-1>", lambda e: self._show_send())

        inbox_card = tk.Frame(btn_frame, bg=BG2, padx=30, pady=24, cursor="hand2")
        inbox_card.grid(row=0, column=1, padx=12)
        tk.Label(inbox_card, text="📥",                  bg=BG2, font=("Segoe UI", 28)).pack()
        tk.Label(inbox_card, text="Inbox",               bg=BG2, fg=TEXT, font=("Segoe UI", 12, "bold")).pack()
        tk.Label(inbox_card, text="Decrypt & download",  bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack()
        for w in [inbox_card] + inbox_card.winfo_children():
            w.bind("<Button-1>", lambda e: self._show_inbox())

        info = tk.Frame(body, bg=BG2, padx=16, pady=12)
        info.pack(fill="x", pady=(28, 0))
        pub = str(self.public_key)
        pub_short = pub[:16] + "..." + pub[-8:]
        tk.Label(info, text=f"Your public key  (on server) : {pub_short}",
                 bg=BG2, fg=TEXT2, font=("Courier", 9)).pack(anchor="w")
        tk.Label(info, text="Your private key (on this PC): stored encrypted on disk",
                 bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

        self._btn(body, "Sign Out", self._signout, color=BG2).pack(pady=(20, 0))

    def _signout(self):
        self.token = self.username = self.private_key = self.public_key = None
        self._show_login()

    def _show_send(self):
        self._clear()

        hdr = tk.Frame(self.root, bg=BG2, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="📤  Send Encrypted File", bg=BG2, fg=TEXT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)
        self._btn(hdr, "← Back", self._show_dashboard, color=BG2).pack(side="right", padx=12)

        body = tk.Frame(self.root, bg=BG, padx=40, pady=20)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Recipient", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        self.recv_var  = tk.StringVar()
        self.recv_menu = tk.OptionMenu(body, self.recv_var, "Loading...")
        self.recv_menu.config(bg=BG2, fg=TEXT, font=("Segoe UI", 10),
                              relief="flat", highlightthickness=0)
        self.recv_menu.pack(fill="x", pady=(2, 12))

        tk.Label(body, text="File", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        file_row = tk.Frame(body, bg=BG)
        file_row.pack(fill="x", pady=(2, 12))
        self.file_path = tk.StringVar(value="No file selected")
        tk.Label(file_row, textvariable=self.file_path, bg=BG2, fg=TEXT2,
                 font=("Segoe UI", 9), padx=8, pady=8, anchor="w").pack(side="left", fill="x", expand=True)
        self._btn(file_row, "Browse", self._pick_file, color=BG2).pack(side="right", padx=(8, 0))


        tk.Label(body, text="Encryption Log", bg=BG, fg=TEXT2, font=("Segoe UI", 9)).pack(anchor="w")
        self.send_log = scrolledtext.ScrolledText(body, bg=BG2, fg=TEXT,
            font=("Courier", 9), height=8, relief="flat", state="disabled")
        self.send_log.pack(fill="x", pady=(2, 12))

        self.send_btn = self._btn(body, "🔒  Encrypt & Send", self._do_send)
        self.send_btn.pack(fill="x")

        def load_users():
            try:
                users = [u["username"] for u in api_get_users(self.token)
                         if u["username"] != self.username]
                def update():
                    menu = self.recv_menu["menu"]
                    menu.delete(0, "end")
                    for u in users:
                        menu.add_command(label=u, command=lambda v=u: self.recv_var.set(v))
                    self.recv_var.set(users[0] if users else "No other users found")
                self.root.after(0, update)
            except Exception:
                pass
        threading.Thread(target=load_users, daemon=True).start()

    def _pick_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def _do_send(self):
        path      = self.file_path.get()
        recipient = self.recv_var.get()

        if path == "No file selected":
            messagebox.showerror("Error", "Please select a file first.")
            return
        if not recipient or recipient in ("No other users found", "Loading..."):
            messagebox.showerror("Error", "Please select a recipient.")
            return

        self.send_btn.config(state="disabled", text="Encrypting...")
        log = self.send_log

        def run():
            try:
                self._log(log, f"[1] Fetching {recipient}'s public key from server...", YELLOW)
                recv_pub = api_get_pubkey(self.token, recipient)
                self._log(log, f"    ReceiverPublicKey = {str(recv_pub)[:20]}...", TEXT2)

                self._log(log, "[2] Computing shared secret (on this PC only)...", YELLOW)
                secret = compute_shared_secret(recv_pub, self.private_key)
                self._log(log, "    Formula: ReceiverPubKey ^ MyPrivateKey mod P", TEXT2)

                self._log(log, "[3] Deriving AES-256 key — SHA256(shared secret)...", YELLOW)
                aes_key = derive_aes_key(secret)
                self._log(log, f"    AES Key = {aes_key.hex()[:24]}... (256-bit)", TEXT2)

                self._log(log, f"[4] Reading file: {os.path.basename(path)}", YELLOW)
                with open(path, "rb") as f:
                    file_bytes = f.read()
                self._log(log, f"    Original size: {len(file_bytes):,} bytes", TEXT2)

                self._log(log, "[5] Encrypting with AES-256...", YELLOW)
                encrypted = encrypt_file(file_bytes, aes_key)
                self._log(log, f"    Encrypted size: {len(encrypted):,} bytes", TEXT2)

                self._log(log, "[6] Uploading ciphertext to server...", YELLOW)
                fid = api_upload(self.token, encrypted,
                                 os.path.basename(path), recipient, self.public_key)
                self._log(log, f"    File ID: {fid}", TEXT2)
                self._log(log, "\n✓  Done! Server only received encrypted bytes.", GREEN)

                self.root.after(0, lambda: self.send_btn.config(
                    state="normal", text="🔒  Encrypt & Send"))

            except Exception as e:
                self._log(log, f"\n✗  Error: {e}", RED)
                self.root.after(0, lambda: self.send_btn.config(
                    state="normal", text="🔒  Encrypt & Send"))

        threading.Thread(target=run, daemon=True).start()

    def _show_inbox(self):
        self._clear()

        hdr = tk.Frame(self.root, bg=BG2, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="📥  Inbox", bg=BG2, fg=TEXT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)
        self._btn(hdr, "← Back",    self._show_dashboard, color=BG2).pack(side="right", padx=12)
        self._btn(hdr, "↻ Refresh", self._show_inbox,     color=BG2).pack(side="right")

        body = tk.Frame(self.root, bg=BG, padx=30, pady=16)
        body.pack(fill="both", expand=True)


        self.inbox_log = scrolledtext.ScrolledText(body, bg=BG2, fg=TEXT,
            font=("Courier", 9), height=6, relief="flat", state="disabled")
        self.inbox_log.pack(fill="x", pady=(0, 12))

        try:
            files = api_inbox(self.token)
        except Exception as e:
            tk.Label(body, text=f"Error: {e}", bg=BG, fg=RED, font=("Segoe UI", 10)).pack()
            return

        if not files:
            tk.Label(body, text="No files received yet.",
                     bg=BG, fg=TEXT2, font=("Segoe UI", 11)).pack(pady=20)
            return

        for f in files:
            row = tk.Frame(body, bg=BG2, padx=14, pady=10)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=f["original_name"],
                     bg=BG2, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(side="left")
            tk.Label(row, text=f"  from {f['sender']}",
                     bg=BG2, fg=TEXT2, font=("Segoe UI", 9)).pack(side="left")
            self._btn(row, "🔓 Decrypt & Save",
                      lambda fdata=f: self._do_decrypt(fdata)).pack(side="right")

    def _do_decrypt(self, fdata):
        log = self.inbox_log

        def run():
            try:
                self._log(log, "[1] Reading sender's public key from file metadata...", YELLOW)
                sender_pub = int(fdata["sender_dh_public_key"])
                self._log(log, f"    SenderPublicKey = {str(sender_pub)[:20]}...", TEXT2)

                self._log(log, "[2] Computing shared secret (on this PC only)...", YELLOW)
                secret = compute_shared_secret(sender_pub, self.private_key)
                self._log(log, "    Formula: SenderPubKey ^ MyPrivateKey mod P", TEXT2)

                self._log(log, "[3] Deriving AES-256 key — SHA256(shared secret)...", YELLOW)
                aes_key = derive_aes_key(secret)
                self._log(log, f"    AES Key = {aes_key.hex()[:24]}... (256-bit)", TEXT2)

                self._log(log, "[4] Downloading encrypted file from server...", YELLOW)
                encrypted = api_download(self.token, fdata["id"])
                self._log(log, f"    Downloaded: {len(encrypted):,} bytes", TEXT2)

                self._log(log, "[5] Decrypting with AES-256...", YELLOW)
                original = decrypt_file(encrypted, aes_key)
                self._log(log, f"    Decrypted: {len(original):,} bytes", TEXT2)

                os.makedirs(DL_DIR, exist_ok=True)
                out = os.path.join(DL_DIR, fdata["original_name"])
                with open(out, "wb") as f:
                    f.write(original)
                self._log(log, f"\n✓  Saved to: {out}", GREEN)

            except Exception as e:
                self._log(log, f"\n✗  Error: {e}", RED)

        threading.Thread(target=run, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg=BG)
    App(root)
    root.mainloop()
