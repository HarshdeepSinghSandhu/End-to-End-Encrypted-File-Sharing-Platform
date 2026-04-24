import os
import sys
import ctypes
import threading
from html import escape

import requests
from PyQt6 import sip
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, Q_ARG, QMetaObject, QSize, QPoint
from PyQt6.QtGui import QColor, QCursor, QFont, QPainter, QPainterPath
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from crypto_engine import (
    compute_shared_secret,
    decrypt_file,
    derive_aes_key,
    encrypt_file,
    generate_dh_keypair,
    has_local_keys,
    load_private_key,
    save_private_key,
)


# -----------------------------------------------------------------------------
# BACKEND WIRING
# -----------------------------------------------------------------------------
SERVER = "https://end-to-end-encrypted-file-sharing.onrender.com"
KEY_DIR = os.path.join(os.path.expanduser("~"), ".secureshare", "keys")
DL_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "SecureShare")


def get_file_type(path):
    with open(path, "rb") as f:
        header = f.read(8)
    if header.startswith(b"\x89PNG"):
        return "png"
    if header.startswith(b"%PDF"):
        return "pdf"
    if header.startswith(b"\xFF\xD8"):
        return "jpg"
    if header.startswith(b"PK"):
        return "zip"
    if header.startswith(b"MZ"):
        return "exe"
    return "unknown"


def api_register(username, email, password, public_key):
    r = requests.post(
        f"{SERVER}/register",
        json={
            "username": username,
            "email": email,
            "password": password,
            "dh_public_key": str(public_key),
        },
    )
    if not r.ok:
        raise Exception(r.json().get("error", "Register failed"))
    return r.json()["token"]


def api_login(username, password):
    r = requests.post(f"{SERVER}/login", json={"username": username, "password": password})
    if not r.ok:
        raise Exception(r.json().get("error", "Login failed"))
    return r.json()["token"]


def api_get_pubkey(token, username):
    r = requests.get(f"{SERVER}/users/{username}/pubkey", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Could not fetch public key"))
    return int(r.json()["dh_public_key"])


def api_upload(token, encrypted_bytes, filename, recipient, sender_pub):
    r = requests.post(
        f"{SERVER}/upload",
        headers={"X-Auth-Token": token},
        data={
            "recipient": recipient,
            "original_filename": filename,
            "sender_dh_public_key": str(sender_pub),
        },
        files={"encrypted_file": (filename, encrypted_bytes)},
    )
    if not r.ok:
        raise Exception(r.json().get("error", "Upload failed"))
    return r.json()["file_id"]


def api_inbox(token):
    r = requests.get(f"{SERVER}/files/inbox", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Inbox failed"))
    return r.json().get("files", [])


def api_download(token, file_id):
    r = requests.get(f"{SERVER}/files/{file_id}", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Download failed"))
    return r.content


def api_send_request(token, target):
    r = requests.post(f"{SERVER}/contacts/request/{target}", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Request failed"))
    return r.json()["message"]


def api_accept_request(token, sender):
    r = requests.post(f"{SERVER}/contacts/accept/{sender}", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Accept failed"))
    return r.json()["message"]


def api_get_contacts(token):
    r = requests.get(f"{SERVER}/contacts", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Contacts failed"))
    return r.json().get("contacts", [])


def api_get_requests(token):
    r = requests.get(f"{SERVER}/contacts/requests", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Requests failed"))
    return r.json().get("requests", [])


def api_get_logs(token):
    r = requests.get(f"{SERVER}/logs", headers={"X-Auth-Token": token})
    if not r.ok:
        raise Exception(r.json().get("error", "Logs failed"))
    return r.json().get("logs", [])


# -----------------------------------------------------------------------------
# UI TOKENS
# -----------------------------------------------------------------------------
C = {
    "page": "#D9E1ED",
    "page2": "#D1DAE8",
    "surface": "#EFF4FB",
    "surface2": "#E8EEF8",
    "surface3": "#E8EDF6",
    "sidebar": "#121426",
    "sidebar2": "#1A1D33",
    "sidebar_border": "#2A2E48",
    "text": "#0B1020",
    "muted": "#52607A",
    "soft": "#7B86A2",
    "side_text": "#AAB4D4",
    "side_muted": "#7782A5",
    "border": "#C7D0E4",
    "border2": "#B5C0DA",
    "accent": "#4F46E5",
    "accent2": "#2563EB",
    "accent_soft": "#E4E8FF",
    "blue": "#2563EB",
    "blue_soft": "#DDEBFF",
    "green": "#059669",
    "green_soft": "#D8F7E8",
    "yellow": "#D97706",
    "yellow_soft": "#FFF1C7",
    "red": "#DC2626",
    "red_soft": "#FDE2E2",
    "console": "#0A0D18",
    "console2": "#111629",
    "console_text": "#C8D2F0",
}


QSS = f"""
* {{
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 13px;
    color: {C["text"]};
    outline: none;
}}

QMainWindow, QWidget#root, QWidget#content_area {{
    background: {C["page"]};
}}

QWidget#login_left, QWidget#sidebar {{
    background: {C["sidebar"]};
}}

QWidget#auth_right {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 {C["page"]},
        stop:1 {C["page2"]}
    );
}}

QFrame#login_card {{
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #F5F8FE,
        stop:1 #EEF3FC
    );
    border: 1px solid #C5CEE2;
    border-radius: 24px;
}}

QFrame#card {{
    background: {C["surface"]};
    border: 1px solid {C["border"]};
    border-radius: 18px;
}}

QFrame#subtle_card {{
    background: {C["surface2"]};
    border: 1px solid {C["border"]};
    border-radius: 16px;
}}

QFrame#identity_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #DCEBFF, stop:1 #E8F8EF);
    border: 1px solid #AFC6E7;
    border-radius: 18px;
}}

QLabel#identity_title {{
    color: {C["text"]};
    font-size: 14px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#identity_meta {{
    color: #3F5278;
    font-family: Consolas, "Cascadia Code", monospace;
    font-size: 12px;
    background: transparent;
    border: none;
}}

QFrame#inbox_banner {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #2F337E, stop:1 #2C6FF2);
    border: none;
    border-radius: 18px;
}}

QLabel#inbox_banner_title {{
    color: #FFFFFF;
    font-size: 19px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#inbox_banner_sub {{
    color: rgba(255,255,255,0.84);
    font-size: 13px;
    background: transparent;
    border: none;
}}

QFrame#inbox_topbar {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #D7E7FF, stop:1 #E4EEFF);
    border: 1px solid #9DB7E4;
    border-radius: 16px;
}}

QLabel#inbox_top_title {{
    color: #0F254D;
    font-size: 24px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#inbox_top_sub {{
    color: #415B86;
    font-size: 13px;
    background: transparent;
    border: none;
}}

QFrame#inbox_log_card {{
    background: #EEF3FB;
    border: 1px solid #C5D1E8;
    border-radius: 18px;
}}

QTextEdit#inbox_console {{
    background: #0D1222;
    color: #C9D5F7;
    border: 1px solid #1B2440;
    border-radius: 14px;
    padding: 16px;
    font-family: "Cascadia Code", Consolas, monospace;
    font-size: 12px;
}}

QFrame#inbox_empty_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #F2F7FF, stop:1 #F6FBF8);
    border: 1px solid #C6D5EA;
    border-radius: 18px;
}}

QLabel#inbox_empty_title {{
    color: {C["text"]};
    font-size: 28px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#inbox_empty_sub {{
    color: {C["muted"]};
    font-size: 14px;
    background: transparent;
    border: none;
}}

QFrame#contacts_topbar {{
    background-color: #4D67E8;
    border: 1px solid #3A58C6;
    border-radius: 16px;
}}

QLabel#contacts_top_title {{
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#contacts_top_sub {{
    color: rgba(245,248,255,0.93);
    font-size: 13px;
    background: transparent;
    border: none;
}}

QPushButton#contacts_refresh_btn {{
    background: rgba(255,255,255,0.14);
    color: #FFFFFF;
    border: 1px solid rgba(255,255,255,0.30);
    border-radius: 12px;
    min-height: 40px;
    font-weight: 800;
    padding: 0 18px;
}}

QPushButton#contacts_refresh_btn:hover {{
    background: rgba(255,255,255,0.22);
    border-color: rgba(255,255,255,0.46);
}}

QFrame#send_topbar {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #3B46B3, stop:0.52 #4B63D6, stop:1 #3F86F2);
    border: 1px solid #324CAA;
    border-radius: 16px;
}}

QLabel#send_top_title {{
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#send_top_sub {{
    color: rgba(244,248,255,0.90);
    font-size: 13px;
    background: transparent;
    border: none;
}}

QFrame#send_recipient_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #DEE9FF, stop:1 #EDF4FF);
    border: 1px solid #AEC4EA;
    border-radius: 18px;
}}

QFrame#send_file_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #E6EDFF, stop:1 #F2F6FF);
    border: 1px solid #B7C9EB;
    border-radius: 18px;
}}

QFrame#send_log_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #E7EEFF, stop:1 #F2F6FF);
    border: 1px solid #B7C9EB;
    border-radius: 18px;
}}

QLabel#send_hint {{
    color: #61749A;
    font-size: 12px;
    font-weight: 700;
    background: transparent;
    border: none;
}}

QPushButton#send_browse_btn {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #F9FBFF, stop:1 #EAF0FF);
    color: #223665;
    border: 1px solid #A8BDE7;
    border-radius: 12px;
    min-height: 46px;
    font-weight: 800;
    padding: 0 18px;
}}

QPushButton#send_browse_btn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #F2F7FF, stop:1 #DEE9FF);
    border-color: #7F9DDB;
}}

QFrame#contacts_add_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #C8DAFF, stop:0.58 #D8E6FF, stop:1 #E3EEFF);
    border: 1px solid #8FAEE4;
    border-radius: 18px;
}}

QFrame#contacts_pending_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #FFF6E6, stop:1 #FFF9F0);
    border: none;
    border-radius: 18px;
}}

QFrame#contacts_network_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #F0F7FF, stop:1 #F7FBFF);
    border: 1px solid #C9D9EF;
    border-radius: 18px;
}}

QLineEdit#contacts_field {{
    background: #FFFFFF;
    border: 1px solid #AFC5E8;
    border-radius: 12px;
    padding: 0 15px;
    min-height: 48px;
    color: {C["text"]};
}}

QLineEdit#contacts_field:hover {{
    border-color: #8EA9D9;
}}

QLineEdit#contacts_field:focus {{
    border: 2px solid #2B64E9;
    padding: 0 14px;
}}

QPushButton#contacts_send_btn {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #477FEF, stop:1 #2B64E9);
    color: #FFFFFF;
    border: 1px solid #2050C7;
    border-radius: 12px;
    min-height: 46px;
    font-weight: 800;
    padding: 0 18px;
}}

QPushButton#contacts_send_btn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #5790F1, stop:1 #2F69EB);
}}

QPushButton#contacts_send_btn:pressed {{
    background: #2458D7;
}}

QLabel#contacts_empty_title {{
    color: {C["text"]};
    font-size: 22px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#contacts_empty_sub {{
    color: {C["muted"]};
    font-size: 14px;
    background: transparent;
    border: none;
}}

QFrame#logs_topbar {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #3F4FCB, stop:0.55 #4F68DB, stop:1 #6087EF);
    border: 1px solid #3652BA;
    border-radius: 16px;
}}

QLabel#logs_top_title {{
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 850;
    background: transparent;
    border: none;
}}

QLabel#logs_top_sub {{
    color: rgba(245,248,255,0.92);
    font-size: 13px;
    background: transparent;
    border: none;
}}

QFrame#logs_activity_card {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #D2E0FF, stop:0.62 #E0EAFF, stop:1 #EBF2FF);
    border: 1px solid #96B0DF;
    border-radius: 18px;
}}

QTextEdit#logs_console {{
    background: #0B1123;
    color: #C9D5F7;
    border: 1px solid #1F2B4B;
    border-radius: 14px;
    padding: 16px;
    font-family: "Cascadia Code", Consolas, monospace;
    font-size: 12px;
}}

QPushButton#logs_refresh_btn {{
    background: rgba(255,255,255,0.14);
    color: #FFFFFF;
    border: 1px solid rgba(255,255,255,0.32);
    border-radius: 12px;
    min-height: 40px;
    font-weight: 800;
    padding: 0 18px;
}}

QPushButton#logs_refresh_btn:hover {{
    background: rgba(255,255,255,0.22);
    border-color: rgba(255,255,255,0.48);
}}

QLabel {{
    background: transparent;
    border: none;
}}

QLabel#brand_big {{
    color: white;
    font-size: 34px;
    font-weight: 800;
    letter-spacing: 0.3px;
}}

QLabel#brand_small {{
    color: white;
    font-size: 16px;
    font-weight: 800;
}}

QLabel#sidebar_caption, QLabel#section_label {{
    color: {C["soft"]};
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.2px;
}}

QLabel#auth_title {{
    color: {C["text"]};
    font-size: 30px;
    font-weight: 850;
    letter-spacing: -0.2px;
}}

QLabel#auth_subtitle {{
    color: {C["muted"]};
    font-size: 14px;
}}

QLabel#auth_field_label {{
    color: #6278A3;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 0.9px;
}}

QLabel#page_title {{
    color: {C["text"]};
    font-size: 27px;
    font-weight: 850;
}}

QLabel#page_subtitle {{
    color: {C["muted"]};
    font-size: 14px;
}}

QLabel#small_muted {{
    color: {C["soft"]};
    font-size: 12px;
}}

QLabel#success_label {{
    color: {C["green"]};
    font-weight: 700;
}}

QLabel#error_label {{
    color: {C["red"]};
    font-weight: 700;
}}

QLineEdit#field, QComboBox {{
    background: {C["surface2"]};
    border: 1px solid {C["border"]};
    border-radius: 12px;
    padding: 0 15px;
    min-height: 46px;
    color: {C["text"]};
    selection-background-color: {C["accent_soft"]};
}}

QLineEdit#field:hover, QComboBox:hover {{
    background: #FAFBFE;
    border-color: {C["border2"]};
}}

QLineEdit#field:focus, QComboBox:focus {{
    background: #FFFFFF;
    border: 2px solid {C["accent"]};
    padding: 0 14px;
}}

QLineEdit#auth_field {{
    background: #F9FBFF;
    border: 2px solid #B8C6E3;
    border-radius: 12px;
    padding: 0 15px;
    min-height: 48px;
    color: {C["text"]};
    selection-background-color: {C["accent_soft"]};
}}

QLineEdit#auth_field:hover {{
    background: #FFFFFF;
    border-color: #97AAD4;
}}

QLineEdit#auth_field:focus {{
    background: #FFFFFF;
    border: 2px solid #2563EB;
    padding: 0 15px;
}}

QComboBox::drop-down {{
    width: 34px;
    border: none;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {C["muted"]};
    margin-right: 14px;
}}

QComboBox QAbstractItemView {{
    background: #FFFFFF;
    border: 1px solid {C["border"]};
    border-radius: 10px;
    padding: 6px;
    selection-background-color: {C["accent_soft"]};
    selection-color: {C["accent"]};
}}

QPushButton {{
    border: none;
    border-radius: 10px;
    font-weight: 700;
}}

QPushButton#btn_primary {{
    background: {C["accent"]};
    color: white;
    padding: 0 22px;
    min-height: 44px;
}}

QPushButton#btn_primary:hover {{
    background: #4338CA;
}}

QPushButton#btn_primary:pressed {{
    background: #3730A3;
}}

QPushButton#btn_primary:disabled {{
    background: #A5B4FC;
    color: rgba(255,255,255,0.75);
}}

QPushButton#btn_secondary {{
    background: {C["surface"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    padding: 0 18px;
    min-height: 42px;
}}

QPushButton#btn_secondary:hover {{
    background: {C["accent_soft"]};
    border-color: #A9B7FF;
    color: {C["accent"]};
}}

QPushButton#btn_ghost {{
    background: transparent;
    color: {C["muted"]};
    border: 1px solid {C["border"]};
    padding: 0 18px;
    min-height: 40px;
}}

QPushButton#btn_ghost:hover {{
    background: {C["surface"]};
    color: {C["accent"]};
    border-color: #A9B7FF;
}}

QPushButton#btn_success {{
    background: {C["green"]};
    color: white;
    padding: 0 16px;
    min-height: 36px;
}}

QPushButton#btn_success:hover {{
    background: #047857;
}}

QPushButton#tab_active {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #5F57EC, stop:1 #4F46E5);
    color: white;
    border: 1px solid #4338CA;
    border-radius: 11px;
    padding: 0 18px;
    min-height: 40px;
    font-weight: 800;
}}

QPushButton#tab_inactive {{
    background: #E5EAF5;
    color: {C["muted"]};
    border: 1px solid #D0D8E8;
    border-radius: 11px;
    padding: 0 18px;
    min-height: 40px;
    font-weight: 700;
}}

QPushButton#tab_inactive:hover {{
    background: #EEF3FC;
    color: {C["text"]};
}}

QFrame#tab_bar {{
    background: #EEF2FA;
    border: 1px solid #D6DEED;
    border-radius: 13px;
}}

QFrame#feature_row {{
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 14px;
}}

QLabel#feature_badge {{
    background: rgba(255,255,255,0.11);
    border: 1px solid rgba(255,255,255,0.20);
    border-radius: 10px;
    color: white;
    font-size: 11px;
    font-weight: 900;
    min-width: 42px;
    min-height: 30px;
}}

QLabel#feature_text {{
    color: rgba(255,255,255,0.90);
    font-size: 13px;
    font-weight: 650;
}}

QLabel#feature_icon {{
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 11px;
    font-size: 16px;
}}

QLabel#feature_chip {{
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.13);
    border-radius: 11px;
    color: rgba(255,255,255,0.92);
    font-size: 14px;
    font-weight: 650;
    padding: 4px 12px;
}}

QPushButton#auth_submit {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #3B82F6, stop:1 #2563EB);
    color: white;
    border: 1px solid #1D4ED8;
    border-radius: 13px;
    font-size: 14px;
    font-weight: 800;
    min-height: 52px;
}}

QPushButton#auth_submit:hover {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #4A8DF7, stop:1 #2B66E9);
}}

QPushButton#auth_submit:pressed {{
    background: #1D4ED8;
}}

QPushButton#auth_submit:disabled {{
    background: #93C5FD;
    border-color: #60A5FA;
    color: rgba(255,255,255,0.80);
}}

QPushButton#nav_btn, QPushButton#nav_btn_active {{
    text-align: left;
    padding-left: 20px;
    min-height: 48px;
    border-radius: 12px;
}}

QPushButton#nav_btn {{
    background: transparent;
    color: {C["side_text"]};
    font-weight: 600;
}}

QPushButton#nav_btn:hover {{
    background: {C["sidebar2"]};
    color: white;
}}

QPushButton#nav_btn_active {{
    background: #202446;
    color: white;
    border: 1px solid #3D3A86;
    font-weight: 800;
}}

QPushButton#signout_btn {{
    background: transparent;
    color: {C["side_text"]};
    border: 1px solid #333851;
    min-height: 38px;
}}

QPushButton#signout_btn:hover {{
    background: rgba(220,38,38,0.14);
    color: #FCA5A5;
    border-color: rgba(220,38,38,0.45);
}}

QFrame#user_chip {{
    background: rgba(255,255,255,0.065);
    border: 1px solid rgba(255,255,255,0.11);
    border-radius: 15px;
}}

QFrame#user_chip:hover {{
    background: rgba(255,255,255,0.10);
    border: 1px solid rgba(255,255,255,0.18);
}}

QLabel#user_chip_name {{
    color: white;
    font-weight: 800;
    font-size: 13px;
    background: transparent;
    border: none;
}}

QLabel#user_chip_role {{
    color: {C["side_text"]};
    font-size: 12px;
    background: transparent;
    border: none;
}}

QTextEdit#console {{
    background: {C["console"]};
    color: {C["console_text"]};
    border: 1px solid #1B2238;
    border-radius: 14px;
    padding: 16px;
    font-family: "Cascadia Code", Consolas, monospace;
    font-size: 12px;
}}

QScrollArea {{
    border: none;
    background: transparent;
}}

QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 8px 2px;
}}

QScrollBar::handle:vertical {{
    background: #B7C1D7;
    border-radius: 4px;
    min-height: 42px;
}}

QScrollBar::handle:vertical:hover {{
    background: #8F9AB4;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
    background: none;
}}
"""


# -----------------------------------------------------------------------------
# SMALL UI HELPERS
# -----------------------------------------------------------------------------
def polish(widget):
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def alive(widget):
    try:
        return widget is not None and not sip.isdeleted(widget)
    except Exception:
        return False


def clear_layout(layout):
    if layout is None:
        return
    while layout.count():
        item = layout.takeAt(0)
        child = item.widget()
        child_layout = item.layout()
        if child is not None:
            child.deleteLater()
        elif child_layout is not None:
            clear_layout(child_layout)


def add_shadow(widget, blur=28, y=8, alpha=0.13):
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, y)
    effect.setColor(QColor(27, 38, 68, int(255 * alpha)))
    widget.setGraphicsEffect(effect)
    return effect


def label(text, obj=None, wrap=False):
    w = QLabel(text)
    if obj:
        w.setObjectName(obj)
    w.setWordWrap(wrap)
    return w


def section_label(text):
    return label(text.upper(), "section_label")


def field(placeholder="", password=False):
    w = QLineEdit()
    w.setObjectName("field")
    w.setPlaceholderText(placeholder)
    if password:
        w.setEchoMode(QLineEdit.EchoMode.Password)
    return w


def auth_field(placeholder="", password=False):
    w = field(placeholder, password=password)
    w.setObjectName("auth_field")
    w.setFixedHeight(50)
    w.setStyleSheet(
        f"QLineEdit {{ background:#FFFFFF; border:2px solid #9AAED4; border-radius:12px; "
        f"padding:0 15px; color:{C['text']}; }}"
        "QLineEdit:hover { border-color:#748CBC; }"
        "QLineEdit:focus { border-color:#2563EB; }"
    )
    return w


def button(text, obj="btn_primary"):
    w = QPushButton(text)
    w.setObjectName(obj)
    w.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
    return w


def card(obj="card"):
    w = QFrame()
    w.setObjectName(obj)
    add_shadow(w, blur=26, y=7, alpha=0.10)
    return w


def divider():
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background:{C['sidebar_border']}; border:none;")
    return line


def danger_exts():
    return (".exe", ".bat", ".cmd", ".sh", ".js", ".msi")


class AvatarWidget(QWidget):
    PALETTE = ["#4F46E5", "#0EA5E9", "#059669", "#D97706", "#7C3AED", "#DC2626"]

    def __init__(self, username, size=40, parent=None):
        super().__init__(parent)
        self.username = username or "?"
        self.size = size
        self.setFixedSize(size, size)
        idx = sum(ord(ch) for ch in self.username) % len(self.PALETTE)
        self.color = QColor(self.PALETTE[idx])

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.size, self.size, self.size / 2, self.size / 2)
        painter.fillPath(path, self.color)
        painter.setPen(QColor("white"))
        painter.setFont(QFont("Segoe UI", max(10, self.size // 3), QFont.Weight.Bold))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.username[0].upper())


class IconBox(QFrame):
    def __init__(self, text, bg, fg, size=52, parent=None, font_px=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        radius = max(10, int(size * 0.27))
        self.setStyleSheet(f"background:{bg}; border:none; border-radius:{radius}px;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        icon = QLabel(text)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if font_px is None:
            font_px = max(14, int(size * (0.40 if len(text) <= 2 else 0.28)))
        icon.setStyleSheet(f"color:{fg}; font-size:{font_px}px; font-weight:900;")
        layout.addWidget(icon)


class StatCard(QFrame):
    clicked = pyqtSignal()

    def __init__(self, icon, title, subtitle, bg, fg, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setMinimumHeight(154)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        add_shadow(self, blur=24, y=7, alpha=0.10)
        self.normal = (
            f"QFrame#card {{ background:{C['surface']}; border:1px solid {C['border']}; "
            "border-radius:18px; }}"
        )
        self.hover = (
            f"QFrame#card {{ background:#FBFCFF; border:1px solid {fg}; "
            "border-radius:18px; }}"
        )
        self.setStyleSheet(self.normal)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)
        layout.addWidget(IconBox(icon, bg, fg, 58), alignment=Qt.AlignmentFlag.AlignTop)

        copy = QVBoxLayout()
        copy.setSpacing(8)
        title_w = QLabel(title)
        title_w.setStyleSheet(f"font-size:15px; font-weight:850; color:{C['text']};")
        sub_w = QLabel(subtitle)
        sub_w.setWordWrap(True)
        sub_w.setStyleSheet(f"font-size:13px; color:{C['muted']};")
        copy.addStretch()
        copy.addWidget(title_w)
        copy.addWidget(sub_w)
        copy.addStretch()
        layout.addLayout(copy, stretch=1)

    def mousePressEvent(self, event):
        self.clicked.emit()

    def enterEvent(self, event):
        self.setStyleSheet(self.hover)

    def leaveEvent(self, event):
        self.setStyleSheet(self.normal)


class FilePathWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("file_drop")
        self.empty_style = (
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #F7FAFF, stop:1 #EEF3FF); "
            "border:1px solid #B5C8EB; border-radius:13px;"
        )
        self.filled_style = (
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #DEE8FF, stop:1 #EAF1FF); "
            "border:1px solid #8EA7DA; "
            "border-radius:13px;"
        )
        self.setStyleSheet(self.empty_style)
        self.setMinimumHeight(64)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 16, 10)
        layout.setSpacing(12)
        self.icon_wrap = QFrame()
        self.icon_wrap.setFixedSize(42, 42)
        self.icon_wrap.setStyleSheet(
            "background:#E5ECFF; border:1px solid #C3D3F6; border-radius:12px;"
        )
        iw = QVBoxLayout(self.icon_wrap)
        iw.setContentsMargins(0, 0, 0, 0)
        self.icon = QLabel("📄")
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setStyleSheet("font-size:20px; border:none; background:transparent;")
        iw.addWidget(self.icon)
        self.text = QLabel("Click Browse to select a file")
        self.text.setStyleSheet(f"color:{C['muted']}; font-style:italic; font-size:13px;")
        self.text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout.addWidget(self.icon_wrap)
        layout.addWidget(self.text)

    def set_path(self, path):
        ext = os.path.splitext(path)[1].lower()
        icon_map = {
            ".pdf": "📄",
            ".png": "🖼",
            ".jpg": "🖼",
            ".jpeg": "🖼",
            ".zip": "🗜",
            ".txt": "📝",
            ".mp4": "🎬",
            ".mp3": "🎵",
            ".exe": "⚠",
        }
        self.icon.setText(icon_map.get(ext, "📎"))
        self.text.setText(os.path.basename(path))
        self.text.setStyleSheet(f"color:{C['accent']}; font-weight:800; font-size:13px;")
        self.setStyleSheet(self.filled_style)


class ContactRow(QFrame):
    def __init__(self, username, pubkey_short="", parent=None):
        super().__init__(parent)
        self.setObjectName("subtle_card")
        self.setMinimumHeight(64)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(14)
        layout.addWidget(AvatarWidget(username, 38))

        copy = QVBoxLayout()
        copy.setSpacing(3)
        name = QLabel(username)
        name.setStyleSheet(f"font-size:14px; font-weight:800; color:{C['text']};")
        status = QLabel("Connected")
        status.setStyleSheet(f"font-size:12px; font-weight:700; color:{C['green']};")
        copy.addWidget(name)
        copy.addWidget(status)
        layout.addLayout(copy)
        layout.addStretch()

        if pubkey_short:
            key = QLabel(f"key {pubkey_short}")
            key.setStyleSheet(
                f"font-family:Consolas; font-size:11px; color:{C['soft']};"
            )
            layout.addWidget(key)


class PendingRow(QFrame):
    accepted = pyqtSignal(str)

    def __init__(self, sender, parent=None):
        super().__init__(parent)
        self.sender = sender
        self.setMinimumHeight(64)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2F337E,
                    stop:0.55 #4F46E5,
                    stop:1 #2C6FF2
                );
                border: 1px solid #324CAA;
                border-radius: 14px;
            }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(14)
        layout.addWidget(AvatarWidget(sender, 38))

        copy = QVBoxLayout()
        copy.setSpacing(3)
        name = QLabel(sender)
        name.setStyleSheet("""
            font-weight:850;
            color:#FFFFFF;
            background:transparent;
            border:none;
        """)
        msg = QLabel("Wants to connect with you")
        msg.setStyleSheet("""
            font-size:12px;
            color:rgba(255,255,255,0.85);
            font-weight:700;
            background:transparent;
            border:none;
        """)
        copy.addWidget(name)
        copy.addWidget(msg)
        layout.addLayout(copy)
        layout.addStretch()

        accept = button("Accept", "btn_primary")
        accept.setFixedWidth(96)
        accept.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #477FEF, stop:1 #2B64E9); "
            "color: #FFFFFF; border: 1px solid #2050C7; border-radius: 12px; "
            "min-height: 36px; font-weight: 800; padding: 0 18px; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #5790F1, stop:1 #2F69EB); }"
            "QPushButton:pressed { background: #2458D7; }"
        )
        accept.clicked.connect(lambda: self.accepted.emit(self.sender))
        layout.addWidget(accept)



class InboxRow(QFrame):
    decrypt_clicked = pyqtSignal(dict)

    def __init__(self, file_data, parent=None):
        super().__init__(parent)
        self.file_data = file_data
        self.setObjectName("card")
        self.setMinimumHeight(82)
        add_shadow(self, blur=20, y=6, alpha=0.09)
        self.normal = (
            f"QFrame#card {{ background:{C['surface']}; border:1px solid {C['border']}; "
            "border-radius:16px; }}"
        )
        self.hover = (
            f"QFrame#card {{ background:#FBFCFF; border:1px solid #A9B7FF; "
            "border-radius:16px; }}"
        )
        self.setStyleSheet(self.normal)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(22, 16, 22, 16)
        layout.setSpacing(16)

        ext = os.path.splitext(file_data["original_name"])[1].lower().replace(".", "")
        layout.addWidget(IconBox((ext[:4] or "FILE").upper(), C["accent_soft"], C["accent"], 52))

        copy = QVBoxLayout()
        copy.setSpacing(5)
        name = QLabel(file_data["original_name"])
        name.setStyleSheet(f"font-size:14px; font-weight:850; color:{C['text']};")
        meta = QLabel(f"From {file_data['sender']}  |  {file_data.get('timestamp', '')}")
        meta.setStyleSheet(f"font-size:12px; color:{C['muted']};")
        copy.addWidget(name)
        copy.addWidget(meta)
        layout.addLayout(copy)
        layout.addStretch()

        decrypt = button("Decrypt && Save", "btn_primary")
        decrypt.setFixedWidth(152)
        decrypt.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #223E9E, stop:0.52 #365FE0, stop:1 #2A86F4); "
            "color: #FFFFFF; border: 1px solid #214DAF; border-radius: 14px; "
            "font-size: 13px; font-weight: 900; padding: 0 20px; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #2846AA, stop:0.52 #4068E8, stop:1 #3390F8); }"
            "QPushButton:pressed { background: #234DBA; }"
            "QPushButton:disabled { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #7F9DDE, stop:1 #9AB6F0); "
            "color: rgba(255,255,255,0.92); border: 1px solid #7D9AD9; }"
        )
        decrypt.clicked.connect(lambda: self.decrypt_clicked.emit(self.file_data))
        layout.addWidget(decrypt)
    def enterEvent(self, event):
        self.setStyleSheet(self.hover)

    def leaveEvent(self, event):
        self.setStyleSheet(self.normal)


# -----------------------------------------------------------------------------
# APPLICATION
# -----------------------------------------------------------------------------
class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.token = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self._selected_file = None
        self._account_popup = None
        self._user_chip = None
        self._recv_combo = None
        self._send_btn = None
        self.send_log = None
        self.inbox_log = None
        self._add_field = None
        self._contact_msg = None

        self.setWindowTitle("SecureShare")
        self.resize(1120, 720)
        self.setMinimumSize(900, 620)
        self.setObjectName("root")
        self.setStyleSheet(QSS)

        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)
        self._login_w = QWidget()
        self._main_w = QWidget()
        self._stack.addWidget(self._login_w)
        self._stack.addWidget(self._main_w)
        self._build_login()
        self._stack.setCurrentWidget(self._login_w)

    # ------------------------------------------------------------------ LOGIN
    def _build_login(self):
        root = QHBoxLayout(self._login_w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        left = QWidget()
        left.setObjectName("login_left")
        left.setFixedWidth(410)
        left.setStyleSheet(
            f"QWidget#login_left {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1, "
            f"stop:0 {C['sidebar']}, stop:1 #181C36); }}"
        )
        left_v = QVBoxLayout(left)
        left_v.setContentsMargins(56, 70, 56, 58)
        left_v.setSpacing(0)

        mark = IconBox("🔐", "#2D2A6E", "#FFFFFF", 104, font_px=44)
        left_v.addWidget(mark)
        left_v.addSpacing(32)
        brand = label("SecureShare", "brand_big")
        left_v.addWidget(brand)
        left_v.addSpacing(10)
        tagline = QLabel("End-to-end encrypted file sharing.\nYour keys never leave this device.")
        tagline.setStyleSheet(f"color:{C['side_text']}; font-size:14px;")
        left_v.addWidget(tagline)
        left_v.addSpacing(44)

        features = [
            ("🗝", "Diffie-Hellman Key Exchange"),
            ("🛡", "AES-256-CTR Encryption"),
            ("🔒", "Zero-knowledge Server"),
            ("✅", "Contact Verification"),
        ]
        for icon, text in features:
            pill = QFrame()
            pill.setObjectName("feature_row")
            row = QHBoxLayout(pill)
            row.setContentsMargins(14, 10, 14, 10)
            row.setSpacing(12)
            icon_lbl = QLabel(icon)
            icon_lbl.setObjectName("feature_icon")
            icon_lbl.setFixedSize(42, 32)
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip = QLabel(text)
            chip.setObjectName("feature_chip")
            row.addWidget(icon_lbl)
            row.addWidget(chip)
            row.addStretch()
            left_v.addWidget(pill)
            left_v.addSpacing(10)
        left_v.addStretch()
        root.addWidget(left)

        right = QWidget()
        right_shell = QVBoxLayout(right)
        right_shell.setContentsMargins(0, 0, 0, 0)
        right_shell.setSpacing(0)

        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_scroll.setFrameShape(QFrame.Shape.NoFrame)
        right_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        right_inner = QWidget()
        right_inner.setObjectName("auth_right")
        right_v = QVBoxLayout(right_inner)
        right_v.setContentsMargins(52, 40, 52, 40)
        right_v.setSpacing(0)
        right_v.addStretch()

        form = QFrame()
        form.setObjectName("login_card")
        form.setFixedWidth(500)
        form.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        add_shadow(form, blur=44, y=14, alpha=0.16)
        form_v = QVBoxLayout(form)
        form_v.setContentsMargins(42, 38, 42, 38)
        form_v.setSpacing(0)

        title = label("Welcome Back", "auth_title")
        form_v.addWidget(title)
        form_v.addSpacing(8)
        subtitle = label("Sign in or create a new account to continue.", "auth_subtitle")
        form_v.addWidget(subtitle)
        form_v.addSpacing(24)

        tab_shell = QFrame()
        tab_shell.setObjectName("tab_bar")
        tab_shell_l = QHBoxLayout(tab_shell)
        tab_shell_l.setContentsMargins(8, 8, 8, 8)
        tab_shell_l.setSpacing(8)
        self._tab_mode = "login"
        self._tab_sign = button("Sign In", "tab_active")
        self._tab_register = button("Create Account", "tab_inactive")
        self._tab_sign.clicked.connect(lambda: self._switch_tab("login"))
        self._tab_register.clicked.connect(lambda: self._switch_tab("register"))
        tab_shell_l.addWidget(self._tab_sign)
        tab_shell_l.addWidget(self._tab_register)
        form_v.addWidget(tab_shell)
        form_v.addSpacing(22)

        self._form_stack = QStackedWidget()
        self._form_stack.setStyleSheet("background:transparent; border:none;")
        self._form_stack.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

        login_page = QWidget()
        login_page.setStyleSheet("background:transparent;")
        login_v = QVBoxLayout(login_page)
        login_v.setContentsMargins(0, 0, 0, 0)
        login_v.setSpacing(8)
        login_v.setAlignment(Qt.AlignmentFlag.AlignTop)
        u_lbl = label("USERNAME", "auth_field_label")
        login_v.addWidget(u_lbl)
        self.e_user_l = auth_field("Enter your username")
        login_v.addWidget(self.e_user_l)
        login_v.addSpacing(4)
        p_lbl = label("PASSWORD", "auth_field_label")
        login_v.addWidget(p_lbl)
        self.e_pass_l = auth_field("Enter your password", password=True)
        login_v.addWidget(self.e_pass_l)
        self._form_stack.addWidget(login_page)

        register_page = QWidget()
        register_page.setStyleSheet("background:transparent;")
        register_v = QVBoxLayout(register_page)
        register_v.setContentsMargins(0, 0, 0, 0)
        register_v.setSpacing(8)
        register_v.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.e_user_r = auth_field("Choose a username")
        self.e_email = auth_field("you@example.com")
        self.e_pass_r = auth_field("Min. 6 characters", password=True)
        self.e_pass2 = auth_field("Retype password", password=True)
        for title_text, editor in [
            ("Username", self.e_user_r),
            ("Email Address", self.e_email),
            ("Password", self.e_pass_r),
            ("Confirm Password", self.e_pass2),
        ]:
            register_v.addWidget(label(title_text.upper(), "auth_field_label"))
            register_v.addWidget(editor)
            register_v.addSpacing(4)
        self._form_stack.addWidget(register_page)
        form_v.addWidget(self._form_stack)
        form_v.addSpacing(12)

        self._status_lbl = label("", "error_label", wrap=True)
        self._status_lbl.setMinimumHeight(24)
        form_v.addWidget(self._status_lbl)
        form_v.addSpacing(14)

        self._submit_btn = button("Sign In", "auth_submit")
        self._submit_btn.setFixedHeight(50)
        self._submit_btn.clicked.connect(self._submit)
        form_v.addWidget(self._submit_btn)

        right_v.addWidget(form, alignment=Qt.AlignmentFlag.AlignHCenter)
        right_v.addStretch()
        right_scroll.setWidget(right_inner)
        right_shell.addWidget(right_scroll)
        root.addWidget(right, stretch=1)
        self.setStyleSheet(QSS)
        self._sync_auth_stack_height()
        self.e_user_l.setFocus()

    def _switch_tab(self, mode):
        self._tab_mode = mode
        self._status_lbl.setText("")
        if mode == "login":
            self._form_stack.setCurrentIndex(0)
            self._tab_sign.setObjectName("tab_active")
            self._tab_register.setObjectName("tab_inactive")
            self._submit_btn.setText("Sign In")
        else:
            self._form_stack.setCurrentIndex(1)
            self._tab_sign.setObjectName("tab_inactive")
            self._tab_register.setObjectName("tab_active")
            self._submit_btn.setText("Create Account")
        self._sync_auth_stack_height()
        polish(self._tab_sign)
        polish(self._tab_register)

    def _sync_auth_stack_height(self):
        current = self._form_stack.currentWidget()
        if current is None:
            return
        current_layout = current.layout()
        if current_layout is None:
            return
        current_layout.activate()
        self._form_stack.setFixedHeight(current_layout.sizeHint().height())

    def _submit(self):
        mode = self._tab_mode
        username = (self.e_user_l if mode == "login" else self.e_user_r).text().strip().lower()
        password = (self.e_pass_l if mode == "login" else self.e_pass_r).text().strip()
        email = self.e_email.text().strip().lower()
        pass2 = self.e_pass2.text().strip()

        self._status_lbl.setText("")
        if not username or not password:
            self._status_lbl.setText("Username and password are required.")
            return
        if mode == "register" and (not email or "@" not in email):
            self._status_lbl.setText("A valid email address is required.")
            return
        if mode == "register" and password != pass2:
            self._status_lbl.setText("Passwords do not match.")
            return
        if mode == "register" and len(password) < 6:
            self._status_lbl.setText("Password must be at least 6 characters.")
            return

        self._submit_btn.setEnabled(False)
        self._submit_btn.setText("Please wait...")

        def run():
            try:
                if mode == "register":
                    priv, pub = generate_dh_keypair()
                    token = api_register(username, email, password, pub)
                    save_private_key(priv, pub, username, password, KEY_DIR)
                else:
                    token = api_login(username, password)
                    if not has_local_keys(username, KEY_DIR):
                        raise Exception("No local keys found. Please register first.")
                    priv, pub = load_private_key(username, password, KEY_DIR)
                QMetaObject.invokeMethod(
                    self,
                    "_on_login_ok",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, username),
                    Q_ARG(object, priv),
                    Q_ARG(object, pub),
                    Q_ARG(str, token),
                )
            except Exception as exc:
                QMetaObject.invokeMethod(
                    self,
                    "_on_login_fail",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, str(exc)),
                )

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(str, object, object, str)
    def _on_login_ok(self, username, priv, pub, token):
        self.username = username
        self.private_key = priv
        self.public_key = pub
        self.token = token
        self._build_main()
        self._stack.setCurrentWidget(self._main_w)

    @pyqtSlot(str)
    def _on_login_fail(self, msg):
        self._status_lbl.setText(msg)
        self._submit_btn.setEnabled(True)
        self._submit_btn.setText("Sign In" if self._tab_mode == "login" else "Create Account")

    # --------------------------------------------------------------- MAIN SHELL
    def _build_main(self):
        root = self._main_w.layout()
        if root is None:
            root = QHBoxLayout(self._main_w)
        else:
            while root.count():
                item = root.takeAt(0)
                child = item.widget()
                child_layout = item.layout()
                if child is not None:
                    child.deleteLater()
                elif child_layout is not None:
                    while child_layout.count():
                        nested = child_layout.takeAt(0)
                        nested_widget = nested.widget()
                        if nested_widget is not None:
                            nested_widget.deleteLater()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(282)
        side_v = QVBoxLayout(sidebar)
        side_v.setContentsMargins(0, 0, 0, 0)
        side_v.setSpacing(0)

        brand = QWidget()
        brand.setStyleSheet("background:transparent;")
        brand.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        brand_l = QHBoxLayout(brand)
        brand_l.setContentsMargins(24, 28, 24, 24)
        brand_l.setSpacing(13)
        brand_l.addWidget(IconBox("🔐", "#2D2A6E", "#FFFFFF", 44, font_px=20))
        brand_text = QVBoxLayout()
        brand_text.setSpacing(3)
        brand_text.addWidget(label("SecureShare", "brand_small"))
        sub = QLabel("End-to-end encrypted")
        sub.setStyleSheet(f"color:{C['side_text']}; font-size:12px;")
        brand_text.addWidget(sub)
        brand_l.addLayout(brand_text)
        brand_l.addStretch()
        brand.mousePressEvent = lambda e: self._show_dashboard()
        side_v.addWidget(brand)
        side_v.addWidget(divider())
        side_v.addSpacing(20)

        cap = label("NAVIGATION", "sidebar_caption")
        cap.setStyleSheet(f"padding-left:26px; color:{C['side_muted']};")
        side_v.addWidget(cap)
        side_v.addSpacing(10)

        self._nav_map = {}
        nav_wrap = QWidget()
        nav_wrap.setStyleSheet("background:transparent;")
        nav_v = QVBoxLayout(nav_wrap)
        nav_v.setContentsMargins(14, 0, 14, 0)
        nav_v.setSpacing(7)
        for icon, name, callback in [
            ("📤", "Send File", self._show_send),
            ("📥", "Inbox", self._show_inbox),
            ("👥", "Contacts", self._show_contacts),
            ("📋", "Audit Logs", self._show_logs),
        ]:
            nav = button(f"{icon}   {name}", "nav_btn")
            nav.clicked.connect(callback)
            nav_v.addWidget(nav)
            self._nav_map[name] = nav
        side_v.addWidget(nav_wrap)
        side_v.addStretch()
        side_v.addWidget(divider())

        footer = QWidget()
        footer.setStyleSheet("background:transparent;")
        foot_v = QVBoxLayout(footer)
        foot_v.setContentsMargins(16, 20, 16, 24)
        foot_v.setSpacing(12)
        user_chip = QFrame()
        user_chip.setObjectName("user_chip")
        user_chip.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        user_chip.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        user_chip.setToolTip("View account details")
        self._user_chip = user_chip
        chip_l = QHBoxLayout(user_chip)
        chip_l.setContentsMargins(14, 12, 14, 12)
        chip_l.setSpacing(12)
        chip_l.addWidget(AvatarWidget(self.username, 42))
        user_text = QVBoxLayout()
        user_text.setSpacing(2)
        un = QLabel(self.username)
        un.setObjectName("user_chip_name")
        role = QLabel("Authenticated")
        role.setObjectName("user_chip_role")
        user_text.addWidget(un)
        user_text.addWidget(role)
        chip_l.addLayout(user_text)
        chip_l.addStretch()
        user_chip.mousePressEvent = lambda e: self._show_account_info(user_chip)
        foot_v.addWidget(user_chip)
        signout = button("Sign Out", "signout_btn")
        signout.clicked.connect(self._signout)
        foot_v.addWidget(signout)
        side_v.addWidget(footer)
        root.addWidget(sidebar)

        self._content = QStackedWidget()
        self._content.setObjectName("content_area")
        root.addWidget(self._content, stretch=1)
        self._show_dashboard()

    def _set_nav(self, active):
        for name, nav in self._nav_map.items():
            nav.setObjectName("nav_btn_active" if name == active else "nav_btn")
            polish(nav)

    def _push(self, widget):
        while self._content.count():
            old = self._content.widget(0)
            self._content.removeWidget(old)
            old.deleteLater()
        self._content.addWidget(widget)
        self._content.setCurrentWidget(widget)

    def _scroll_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        inner.setStyleSheet("background:transparent;")
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(46, 42, 46, 42)
        layout.setSpacing(0)
        scroll.setWidget(inner)
        return scroll, layout

    def _header(self, title, subtitle, refresh=None):
        layout = QHBoxLayout()
        left = QVBoxLayout()
        left.setSpacing(8)
        left.addWidget(label(title, "page_title"))
        left.addWidget(label(subtitle, "page_subtitle", wrap=True))
        layout.addLayout(left)
        layout.addStretch()
        if refresh:
            refresh_btn = button("Refresh", "btn_ghost")
            refresh_btn.setFixedWidth(124)
            refresh_btn.clicked.connect(refresh)
            layout.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignTop)
        return layout

    def _signout(self):
        if alive(self._account_popup):
            self._account_popup.close()
        self.token = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self.e_user_l.clear()
        self.e_pass_l.clear()
        self._status_lbl.setText("")
        self._submit_btn.setEnabled(True)
        self._submit_btn.setText("Sign In")
        self._switch_tab("login")
        self._stack.setCurrentWidget(self._login_w)

    def _show_account_info(self, anchor=None):
        if not self.username:
            return
        if self._account_popup is not None:
            self._account_popup.close()

        anchor = anchor or self._user_chip
        popup = QDialog(self, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        popup.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        popup.setFixedWidth(360)
        popup.setStyleSheet(
            """
            QDialog {
                background: #12192C;
                border: 1px solid #27469A;
                border-radius: 16px;
            }
            QLabel#account_title {
                color: #FFFFFF;
                font-size: 15px;
                font-weight: 900;
                background: transparent;
            }
            QLabel#account_user {
                color: #DCE7FF;
                font-size: 14px;
                font-weight: 800;
                background: transparent;
            }
            QLabel#account_label {
                color: #8FA6D7;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.8px;
                background: transparent;
            }
            QLabel#account_value {
                color: #F4F7FF;
                font-size: 12px;
                background: transparent;
            }
            QLabel#account_path {
                color: #C8D4F4;
                font-family: "Cascadia Code", Consolas, monospace;
                font-size: 11px;
                background: transparent;
            }
            QFrame#account_icon {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #2E4DA8, stop:1 #2990F5);
                border: none;
                border-radius: 14px;
            }
            """
        )
        add_shadow(popup, blur=30, y=10, alpha=0.22)

        layout = QVBoxLayout(popup)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        head = QHBoxLayout()
        head.setSpacing(12)
        icon_wrap = QFrame()
        icon_wrap.setObjectName("account_icon")
        icon_wrap.setFixedSize(44, 44)
        icon_l = QVBoxLayout(icon_wrap)
        icon_l.setContentsMargins(0, 0, 0, 0)
        icon_l.addWidget(label("i"), alignment=Qt.AlignmentFlag.AlignCenter)
        icon_wrap.layout().itemAt(0).widget().setStyleSheet(
            "color:white; font-size:22px; font-weight:900; background:transparent;"
        )
        head.addWidget(icon_wrap)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        t1 = QLabel("Account Details")
        t1.setObjectName("account_title")
        t2 = QLabel(f"Signed in as {self.username}")
        t2.setObjectName("account_user")
        titles.addWidget(t1)
        titles.addWidget(t2)
        head.addLayout(titles, 1)
        layout.addLayout(head)

        for title_text, value_text, obj_name in [
            ("STATUS", "Authenticated", "account_value"),
            ("SERVER", SERVER, "account_path"),
            ("DOWNLOADS", DL_DIR, "account_path"),
            ("KEYS", KEY_DIR, "account_path"),
        ]:
            title_label = QLabel(title_text)
            title_label.setObjectName("account_label")
            value_label = QLabel(value_text)
            value_label.setObjectName(obj_name)
            value_label.setWordWrap(True)
            layout.addWidget(title_label)
            layout.addWidget(value_label)

        popup.adjustSize()
        self._account_popup = popup
        popup.destroyed.connect(lambda *_: setattr(self, "_account_popup", None))

        if anchor is not None:
            anchor_pos = anchor.mapToGlobal(QPoint(0, 0))
            screen = QApplication.primaryScreen().availableGeometry()
            x = anchor_pos.x() + (anchor.width() - popup.width()) // 2
            y = anchor_pos.y() - popup.height() - 10
            if x < screen.left() + 8:
                x = screen.left() + 8
            if x + popup.width() > screen.right() - 8:
                x = screen.right() - popup.width() - 8
            if y < screen.top() + 8:
                y = anchor.mapToGlobal(QPoint(0, anchor.height())).y() + 10
            popup.move(x, y)

        popup.show()

    @pyqtSlot(object, str, str)
    def _log_slot(self, console, msg, color):
        if not alive(console):
            return
        try:
            console.append(
                f'<span style="color:{color}; font-family:Cascadia Code, Consolas, monospace; '
                f'font-size:12px;">{escape(msg)}</span>'
            )
        except RuntimeError:
            return

    def _log(self, console, msg, color="#C8D2F0"):
        QMetaObject.invokeMethod(
            self,
            "_log_slot",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(object, console),
            Q_ARG(str, msg),
            Q_ARG(str, color),
        )

    # --------------------------------------------------------------- DASHBOARD
    @pyqtSlot()
    def _show_dashboard(self):
        if hasattr(self, "_nav_map"):
            for nav in self._nav_map.values():
                nav.setObjectName("nav_btn")
                polish(nav)

        scroll, layout = self._scroll_page()

        banner = QFrame()
        banner.setMinimumHeight(188)
        banner.setStyleSheet(
            "QFrame {"
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #2F337E, stop:0.55 #4F46E5, stop:1 #2C6FF2);"
            "border:none; border-radius:22px;"
            "}"
        )
        add_shadow(banner, blur=38, y=12, alpha=0.18)
        b_l = QHBoxLayout(banner)
        b_l.setContentsMargins(34, 28, 34, 28)
        b_l.setSpacing(24)
        copy = QVBoxLayout()
        copy.setSpacing(10)
        eyebrow = QLabel("SECURE DASHBOARD")
        eyebrow.setStyleSheet(
            "color:rgba(255,255,255,0.76); font-size:11px; font-weight:800; "
            "letter-spacing:1.0px; background:transparent; border:none;"
        )
        greet = QLabel(f"Good to see you, {self.username}")
        greet.setStyleSheet(
            "color:white; font-size:25px; font-weight:850; background:transparent; border:none;"
        )
        desc = QLabel(
            "Files are encrypted on your device before upload.\n"
            "The server only receives ciphertext, never your keys."
        )
        desc.setStyleSheet(
            "color:rgba(255,255,255,0.84); font-size:14px; background:transparent; border:none;"
        )
        copy.addWidget(eyebrow)
        copy.addWidget(greet)
        copy.addWidget(desc)
        copy.addStretch()
        b_l.addLayout(copy, stretch=1)
        b_l.addWidget(IconBox("🔐", "rgba(255,255,255,0.16)", "#FFFFFF", 112, font_px=52))
        layout.addWidget(banner)
        layout.addSpacing(34)

        layout.addWidget(section_label("Quick Actions"))
        layout.addSpacing(14)
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(18)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        actions = [
            ("📤", "Send File", "Encrypt and send a file to a contact", self._show_send, C["accent_soft"], C["accent"]),
            ("📥", "Inbox", "Decrypt and save received files", self._show_inbox, C["blue_soft"], C["blue"]),
            ("👥", "Contacts", "Manage trusted contact requests", self._show_contacts, C["green_soft"], C["green"]),
            ("📋", "Audit Logs", "Review your activity history", self._show_logs, C["yellow_soft"], C["yellow"]),
        ]
        for index, (icon, title, sub, callback, bg, fg) in enumerate(actions):
            stat = StatCard(icon, title, sub, bg, fg)
            stat.clicked.connect(callback)
            grid.addWidget(stat, index // 2, index % 2)
        layout.addLayout(grid)
        layout.addSpacing(34)

        layout.addWidget(section_label("Cryptographic Identity"))
        layout.addSpacing(14)
        identity = QFrame()
        identity.setObjectName("identity_card")
        add_shadow(identity, blur=24, y=7, alpha=0.10)
        row = QHBoxLayout(identity)
        row.setContentsMargins(24, 22, 24, 22)
        row.setSpacing(14)
        row.addWidget(
            IconBox(
                "🔐",
                "qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #DDF7E8, stop:1 #C8EFD8)",
                "#0B8D63",
                60,
                font_px=24,
            )
        )
        info = QVBoxLayout()
        info.setSpacing(6)
        title = QLabel("Key Pair - Active and Secured")
        title.setObjectName("identity_title")
        pub = str(self.public_key)
        pub_short = pub[:16] + "..." + pub[-10:] if len(pub) > 30 else pub
        p1 = QLabel(f"Public key   {pub_short}")
        p2 = QLabel("Private key  encrypted locally on disk and never transmitted")
        for item in (p1, p2):
            item.setObjectName("identity_meta")
            item.setWordWrap(True)
        p1.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        info.addWidget(title)
        info.addWidget(p1)
        info.addWidget(p2)
        row.addLayout(info, 1)
        badge = QLabel("Secure")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedSize(100, 42)
        badge.setStyleSheet(
            "background:qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #DCF7E8, stop:1 #C8EFD8); "
            "color:#0B8D63; border-radius:12px; border:1px solid #AFDFC4; font-weight:900;"
        )
        row.addWidget(badge)
        layout.addWidget(identity)
        layout.addStretch()
        self._push(scroll)

    # ---------------------------------------------------------------- SEND FILE
    @pyqtSlot()
    def _show_send(self):
        self._set_nav("Send File")
        scroll, layout = self._scroll_page()
        topbar = QFrame()
        topbar.setObjectName("send_topbar")
        topbar.setStyleSheet(
            """
            QFrame#send_topbar {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #26357D,
                    stop:0.50 #4560DB,
                    stop:1 #2F84ED
                );
                border: 1px solid #304CA8;
                border-radius: 18px;
            }
            """
        )
        add_shadow(topbar, blur=18, y=5, alpha=0.08)
        top_l = QHBoxLayout(topbar)
        top_l.setContentsMargins(18, 16, 18, 16)
        top_l.setSpacing(14)
        top_l.addWidget(IconBox("📤", "rgba(255,255,255,0.18)", "#FFFFFF", 54, font_px=23))
        top_copy = QVBoxLayout()
        top_copy.setSpacing(5)
        top_title = QLabel("Send Encrypted File")
        top_title.setObjectName("send_top_title")
        top_title.setStyleSheet(
            "color:#FFFFFF; font-size:26px; font-weight:900; background:transparent; border:none;"
        )
        top_sub = QLabel("Files are encrypted locally before upload. The server only receives ciphertext.")
        top_sub.setObjectName("send_top_sub")
        top_sub.setStyleSheet(
            "color:rgba(244,248,255,0.92); font-size:14px; background:transparent; border:none;"
        )
        top_sub.setWordWrap(True)
        top_copy.addWidget(top_title)
        top_copy.addWidget(top_sub)
        top_l.addLayout(top_copy, 1)
        layout.addWidget(topbar)
        layout.addSpacing(20)

        recipient_card = card("send_recipient_card")
        recipient_card.setStyleSheet(
            """
            QFrame#send_recipient_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #B7C7FF,
                    stop:0.54 #D1DEFF,
                    stop:1 #EDF3FF
                );
                border: 1px solid #8AA6E3;
                border-radius: 18px;
            }
            """
        )
        recipient_v = QVBoxLayout(recipient_card)
        recipient_v.setContentsMargins(28, 24, 28, 24)
        recipient_v.setSpacing(14)
        top = QHBoxLayout()
        top.addWidget(section_label("Recipient"))
        top.addStretch()
        hint = label("Only contacts can receive files", "send_hint")
        hint.setStyleSheet(
            "color:#506893; font-size:12px; font-weight:800; background:transparent; border:none;"
        )
        top.addWidget(hint)
        recipient_v.addLayout(top)
        self._recv_combo = QComboBox()
        self._recv_combo.addItem("Loading contacts...")
        recipient_v.addWidget(self._recv_combo)
        layout.addWidget(recipient_card)
        layout.addSpacing(18)

        file_card = card("send_file_card")
        file_card.setStyleSheet(
            """
            QFrame#send_file_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #C7D4FF,
                    stop:0.54 #E1E9FF,
                    stop:1 #F3F7FF
                );
                border: 1px solid #9CB4E7;
                border-radius: 18px;
            }
            """
        )
        file_v = QVBoxLayout(file_card)
        file_v.setContentsMargins(28, 24, 28, 24)
        file_v.setSpacing(14)
        file_v.addWidget(section_label("File to Send"))
        file_row = QHBoxLayout()
        file_row.setSpacing(14)
        self._file_display = FilePathWidget()
        file_row.addWidget(self._file_display, stretch=1)
        browse = button("Browse", "send_browse_btn")
        browse.setFixedWidth(126)
        browse.clicked.connect(self._pick_file)
        file_row.addWidget(browse)
        file_v.addLayout(file_row)
        layout.addWidget(file_card)
        layout.addSpacing(18)

        log_card = card("send_log_card")
        log_card.setStyleSheet(
            """
            QFrame#send_log_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #D6E0FF,
                    stop:0.58 #E8EEFF,
                    stop:1 #F7FAFF
                );
                border: 1px solid #A8BCE8;
                border-radius: 18px;
            }
            """
        )
        log_v = QVBoxLayout(log_card)
        log_v.setContentsMargins(28, 24, 28, 24)
        log_v.setSpacing(14)
        hdr = QHBoxLayout()
        hdr.addWidget(section_label("Encryption Log"))
        hdr.addStretch()
        live = QLabel("Live")
        live.setStyleSheet("color:#255FE1; font-weight:850; background:transparent; border:none;")
        hdr.addWidget(live)
        log_v.addLayout(hdr)
        self.send_log = QTextEdit()
        self.send_log.setObjectName("console")
        self.send_log.setReadOnly(True)
        self.send_log.setFixedHeight(210)
        log_v.addWidget(self.send_log)
        layout.addWidget(log_card)
        layout.addSpacing(24)

        self._send_btn = button("Encrypt and Send", "btn_primary")
        self._send_btn.setFixedHeight(50)
        self._send_btn.setStyleSheet(
            """
            QPushButton {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #223E9E,
                    stop:0.52 #365FE0,
                    stop:1 #2A86F4
                );
                color: #FFFFFF;
                border: 1px solid #214DAF;
                border-radius: 14px;
                font-size: 15px;
                font-weight: 900;
                padding: 0 20px;
            }
            QPushButton:hover {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2846AA,
                    stop:0.52 #4068E8,
                    stop:1 #3390F8
                );
            }
            QPushButton:pressed {
                background: #234DBA;
            }
            QPushButton:disabled {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7F9DDE,
                    stop:1 #9AB6F0
                );
                color: rgba(255,255,255,0.92);
                border: 1px solid #7D9AD9;
            }
            """
        )
        self._send_btn.clicked.connect(self._do_send)
        layout.addWidget(self._send_btn)
        layout.addStretch()
        self._push(scroll)
        self._selected_file = None

        def load_contacts():
            try:
                contacts = api_get_contacts(self.token)
                QMetaObject.invokeMethod(
                    self,
                    "_fill_combo",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(object, contacts),
                )
            except Exception:
                QMetaObject.invokeMethod(
                    self,
                    "_fill_combo",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(object, []),
                )

        threading.Thread(target=load_contacts, daemon=True).start()

    @pyqtSlot(object)
    def _fill_combo(self, contacts):
        if not alive(self._recv_combo):
            return
        self._recv_combo.clear()
        if contacts:
            for contact in contacts:
                self._recv_combo.addItem(contact["username"])
        else:
            self._recv_combo.addItem("No contacts yet - add contacts first")

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            self._selected_file = path
            self._file_display.set_path(path)

    def _do_send(self):
        path = self._selected_file
        recipient = self._recv_combo.currentText()
        if not path:
            QMessageBox.warning(self, "No File", "Please select a file first.")
            return
        filename = os.path.basename(path).lower()
        if filename.endswith(danger_exts()) or get_file_type(path) == "exe":
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Warning")
            msg_box.setText(f"{filename} may be dangerous.\nContinue?")
            msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            msg_box.setStyleSheet(
                "QMessageBox { background:#FFFFFF; } QLabel { color:#0B1020; font-size:13px; } QPushButton { background:#4F46E5; color:white; border-radius:8px; padding:6px 18px; font-weight:700; min-width:60px; } QPushButton:hover { background:#4338CA; }")
            if msg_box.exec() != QMessageBox.StandardButton.Yes:
                return
        if not recipient or "No contacts" in recipient or "Loading" in recipient:
            QMessageBox.warning(self, "No Contacts", "Add a contact first.")
            return

        self._send_btn.setEnabled(False)
        self._send_btn.setText("Encrypting...")
        log = self.send_log

        def run():
            try:
                self._log(log, f"[1/6] Fetching {recipient}'s public key...", "#8EA2FF")
                recv_pub = api_get_pubkey(self.token, recipient)
                self._log(log, f"      ReceiverPublicKey = {str(recv_pub)[:24]}...", "#5F6F95")
                self._log(log, "[2/6] Computing shared secret on this PC...", "#8EA2FF")
                secret = compute_shared_secret(recv_pub, self.private_key)
                self._log(log, "[3/6] Deriving AES-256 key via SHA-256...", "#8EA2FF")
                aes_key = derive_aes_key(secret)
                self._log(log, f"      AES key = {aes_key.hex()[:30]}...", "#5F6F95")
                self._log(log, f"[4/6] Reading {os.path.basename(path)}...", "#8EA2FF")
                with open(path, "rb") as f:
                    file_bytes = f.read()
                self._log(log, f"      Original size = {len(file_bytes):,} bytes", "#5F6F95")
                self._log(log, "[5/6] Encrypting with AES-256-CTR...", "#8EA2FF")
                encrypted = encrypt_file(file_bytes, aes_key)
                self._log(log, f"      Encrypted size = {len(encrypted):,} bytes", "#5F6F95")
                self._log(log, "[6/6] Uploading ciphertext to server...", "#8EA2FF")
                file_id = api_upload(
                    self.token,
                    encrypted,
                    os.path.basename(path),
                    recipient,
                    self.public_key,
                )
                self._log(log, f"      File ID = {file_id}", "#5F6F95")
                self._log(log, "Transfer complete. Only encrypted bytes were uploaded.", "#34D399")
            except Exception as exc:
                self._log(log, f"Error: {exc}", "#F87171")
            QMetaObject.invokeMethod(self, "_send_done", Qt.ConnectionType.QueuedConnection)

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot()
    def _send_done(self):
        if not alive(self._send_btn):
            return
        self._send_btn.setEnabled(True)
        self._send_btn.setText("Encrypt and Send")

    # ------------------------------------------------------------------- INBOX
    @pyqtSlot()
    def _show_inbox(self):
        self._set_nav("Inbox")
        scroll, layout = self._scroll_page()
        topbar = QFrame()
        topbar.setObjectName("inbox_topbar")
        topbar.setStyleSheet(
            """
            QFrame#inbox_topbar {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2F3E96,
                    stop:0.52 #4B64DE,
                    stop:1 #3F88F0
                );
                border: 1px solid #3550B3;
                border-radius: 18px;
            }
            """
        )
        add_shadow(topbar, blur=18, y=5, alpha=0.08)
        top_l = QHBoxLayout(topbar)
        top_l.setContentsMargins(18, 16, 18, 16)
        top_l.setSpacing(14)
        top_l.addWidget(IconBox("📥", "#DCEAFE", "#2B64E9", 54, font_px=26))
        top_copy = QVBoxLayout()
        top_copy.setSpacing(5)
        top_title = QLabel("Inbox")
        top_title.setObjectName("inbox_top_title")
        top_title.setStyleSheet(
            "color:#FFFFFF; font-size:24px; font-weight:900; background:transparent; border:none;"
        )
        top_sub = QLabel("Decryption is performed entirely on your device. Keys never leave.")
        top_sub.setObjectName("inbox_top_sub")
        top_sub.setStyleSheet(
            "color:rgba(244,248,255,0.92); font-size:13px; background:transparent; border:none;"
        )
        top_copy.addWidget(top_title)
        top_copy.addWidget(top_sub)
        top_l.addLayout(top_copy, 1)
        ref = button("Refresh", "btn_ghost")
        ref.setFixedWidth(122)
        ref.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,255,255,0.16);
                color: #FFFFFF;
                border: 1px solid rgba(255,255,255,0.32);
                border-radius: 12px;
                font-weight: 800;
                padding: 0 18px;
            }
            QPushButton:hover {
                background: rgba(255,255,255,0.24);
                border: 1px solid rgba(255,255,255,0.46);
            }
            """
        )
        ref.clicked.connect(self._show_inbox)
        top_l.addWidget(ref, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(topbar)
        layout.addSpacing(20)

        inbox_banner = QFrame()
        inbox_banner.setObjectName("inbox_banner")
        inbox_banner.setMinimumHeight(120)
        inbox_banner.setStyleSheet(
            "QFrame {"
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #3444A5, stop:0.55 #4563D9, stop:1 #3D82EA);"
            "border:none; border-radius:18px;"
            "}"
        )
        add_shadow(inbox_banner, blur=26, y=8, alpha=0.15)
        banner_l = QHBoxLayout(inbox_banner)
        banner_l.setContentsMargins(26, 20, 26, 20)
        banner_l.setSpacing(18)
        banner_copy = QVBoxLayout()
        banner_copy.setSpacing(8)
        bt = QLabel("Secure Inbox")
        bt.setObjectName("inbox_banner_title")
        bs = QLabel("Incoming files remain encrypted in transit and decrypt locally on this device.")
        bs.setObjectName("inbox_banner_sub")
        bs.setWordWrap(True)
        banner_copy.addWidget(bt)
        banner_copy.addWidget(bs)
        banner_l.addLayout(banner_copy, 1)
        banner_l.addWidget(IconBox("🔐", "rgba(255,255,255,0.16)", "#FFFFFF", 74, font_px=34))
        layout.addWidget(inbox_banner)
        layout.addSpacing(20)

        log_card = QFrame()
        log_card.setObjectName("inbox_log_card")
        log_card.setStyleSheet(
            """
            QFrame#inbox_log_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #D0DCFF,
                    stop:0.56 #E4EBFF,
                    stop:1 #F4F7FF
                );
                border: 1px solid #A6BAE7;
                border-radius: 18px;
            }
            """
        )
        add_shadow(log_card, blur=22, y=7, alpha=0.10)
        log_v = QVBoxLayout(log_card)
        log_v.setContentsMargins(28, 24, 28, 24)
        log_v.setSpacing(14)
        hdr = QHBoxLayout()
        hdr.addWidget(section_label("Decryption Log"))
        hdr.addStretch()
        live = QLabel("Live")
        live.setStyleSheet("color:#255FE1; font-weight:850; background:transparent; border:none;")
        hdr.addWidget(live)
        log_v.addLayout(hdr)
        self.inbox_log = QTextEdit()
        self.inbox_log.setObjectName("inbox_console")
        self.inbox_log.setReadOnly(True)
        self.inbox_log.setFixedHeight(150)
        log_v.addWidget(self.inbox_log)
        layout.addWidget(log_card)
        layout.addSpacing(24)

        results_host = QWidget()
        results_host.setStyleSheet("background:transparent;")
        results_v = QVBoxLayout(results_host)
        results_v.setContentsMargins(0, 0, 0, 0)
        results_v.setSpacing(0)
        loading_card = QFrame()
        loading_card.setObjectName("inbox_empty_card")
        loading_card.setStyleSheet(
            """
            QFrame#inbox_empty_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #DFE7FF,
                    stop:0.58 #EEF3FF,
                    stop:1 #FBFCFF
                );
                border: 1px solid #B6C7EC;
                border-radius: 18px;
            }
            """
        )
        add_shadow(loading_card, blur=22, y=7, alpha=0.10)
        loading_v = QVBoxLayout(loading_card)
        loading_v.setContentsMargins(38, 34, 38, 34)
        loading_v.setSpacing(10)
        loading_title = QLabel("Loading inbox...")
        loading_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_title.setStyleSheet(
            "color:#101A35; font-size:22px; font-weight:900; background:transparent; border:none;"
        )
        loading_sub = QLabel("Fetching your encrypted files.")
        loading_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_sub.setStyleSheet(
            "color:#536887; font-size:14px; background:transparent; border:none;"
        )
        loading_v.addWidget(loading_title)
        loading_v.addWidget(loading_sub)
        results_v.addWidget(loading_card)
        layout.addWidget(results_host)
        layout.addStretch()
        self._push(scroll)

        def load_inbox():
            try:
                files = api_inbox(self.token)
                QMetaObject.invokeMethod(
                    self,
                    "_render_inbox_results",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(object, results_host),
                    Q_ARG(object, files),
                )
            except Exception as exc:
                QMetaObject.invokeMethod(
                    self,
                    "_render_inbox_error",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(object, results_host),
                    Q_ARG(str, str(exc)),
                )

        threading.Thread(target=load_inbox, daemon=True).start()
        return

        files = None

        if not files:
            empty = QFrame()
            empty.setObjectName("inbox_empty_card")
            empty.setStyleSheet(
                """
                QFrame#inbox_empty_card {
                    background: qlineargradient(
                        x1:0, y1:0, x2:1, y2:1,
                        stop:0 #DFE7FF,
                        stop:0.58 #EEF3FF,
                        stop:1 #FBFCFF
                    );
                    border: 1px solid #B6C7EC;
                    border-radius: 18px;
                }
                """
            )
            add_shadow(empty, blur=22, y=7, alpha=0.10)
            empty_v = QVBoxLayout(empty)
            empty_v.setContentsMargins(42, 48, 42, 48)
            empty_v.setSpacing(12)
            icon = IconBox("🔐", "#E7EEFF", "#355FD5", 76, font_px=34)
            empty_v.addWidget(icon, alignment=Qt.AlignmentFlag.AlignCenter)
            title = QLabel("Your inbox is empty")
            title.setObjectName("inbox_empty_title")
            title.setStyleSheet(
                "color:#101A35; font-size:28px; font-weight:900; background:transparent; border:none;"
            )
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub = QLabel("Encrypted files sent to you will appear here.")
            sub.setObjectName("inbox_empty_sub")
            sub.setStyleSheet(
                "color:#536887; font-size:14px; background:transparent; border:none;"
            )
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_v.addWidget(title)
            empty_v.addWidget(sub)
            layout.addWidget(empty)
        else:
            row = QHBoxLayout()
            row.addWidget(section_label("Received Files"))
            count = QLabel(str(len(files)))
            count.setStyleSheet(
                f"background:{C['blue_soft']}; color:{C['blue']}; border-radius:10px; "
                "padding:3px 11px; font-weight:900;"
            )
            row.addWidget(count)
            row.addStretch()
            layout.addLayout(row)
            layout.addSpacing(14)
            for file_data in files:
                item = InboxRow(file_data)
                item.decrypt_clicked.connect(self._do_decrypt)
                layout.addWidget(item)
                layout.addSpacing(10)
        layout.addStretch()
        self._push(scroll)

    @pyqtSlot(object, object)
    def _render_inbox_results(self, host, files):
        if not alive(host):
            return
        host_layout = host.layout()
        clear_layout(host_layout)
        host_layout.setSpacing(0)

        if not files:
            empty = QFrame()
            empty.setObjectName("inbox_empty_card")
            empty.setStyleSheet(
                """
                QFrame#inbox_empty_card {
                    background: qlineargradient(
                        x1:0, y1:0, x2:1, y2:1,
                        stop:0 #DFE7FF,
                        stop:0.58 #EEF3FF,
                        stop:1 #FBFCFF
                    );
                    border: 1px solid #B6C7EC;
                    border-radius: 18px;
                }
                """
            )
            add_shadow(empty, blur=22, y=7, alpha=0.10)
            empty_v = QVBoxLayout(empty)
            empty_v.setContentsMargins(42, 48, 42, 48)
            empty_v.setSpacing(12)
            icon = IconBox("📥", "#E7EEFF", "#355FD5", 76, font_px=34)
            empty_v.addWidget(icon, alignment=Qt.AlignmentFlag.AlignCenter)
            title = QLabel("Your inbox is empty")
            title.setStyleSheet(
                "color:#101A35; font-size:28px; font-weight:900; background:transparent; border:none;"
            )
            title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub = QLabel("Encrypted files sent to you will appear here.")
            sub.setStyleSheet(
                "color:#536887; font-size:14px; background:transparent; border:none;"
            )
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_v.addWidget(title)
            empty_v.addWidget(sub)
            host_layout.addWidget(empty)
            return

        row = QHBoxLayout()
        row.addWidget(section_label("Received Files"))
        count = QLabel(str(len(files)))
        count.setStyleSheet(
            f"background:{C['blue_soft']}; color:{C['blue']}; border-radius:10px; "
            "padding:3px 11px; font-weight:900;"
        )
        row.addWidget(count)
        row.addStretch()
        host_layout.addLayout(row)
        host_layout.addSpacing(14)
        for file_data in files:
            item = InboxRow(file_data)
            item.decrypt_clicked.connect(self._do_decrypt)
            host_layout.addWidget(item)
            host_layout.addSpacing(10)

    @pyqtSlot(object, str)
    def _render_inbox_error(self, host, msg):
        if not alive(host):
            return
        host_layout = host.layout()
        clear_layout(host_layout)
        host_layout.addWidget(label(f"Error loading inbox: {msg}", "error_label", wrap=True))

    def _do_decrypt(self, file_data):
        log = self.inbox_log
        filename = file_data["original_name"].lower()
        if filename.endswith(danger_exts()) or ".exe" in filename:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Security Warning")
            msg_box.setText(f"{filename} may be dangerous.\nContinue?")
            msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            msg_box.setStyleSheet(
                "QMessageBox { background:#FFFFFF; } QLabel { color:#0B1020; font-size:13px; } QPushButton { background:#4F46E5; color:white; border-radius:8px; padding:6px 18px; font-weight:700; min-width:60px; } QPushButton:hover { background:#4338CA; }")
            if msg_box.exec() != QMessageBox.StandardButton.Yes:
                self._log(log, "[CANCELLED] User aborted download.", "#F87171")
                return

        def run():
            try:
                self._log(log, "[1/5] Reading sender public key from metadata...", "#8EA2FF")
                sender_pub = int(file_data["sender_dh_public_key"])
                self._log(log, f"      SenderPublicKey = {str(sender_pub)[:24]}...", "#5F6F95")
                self._log(log, "[2/5] Computing shared secret...", "#8EA2FF")
                secret = compute_shared_secret(sender_pub, self.private_key)
                self._log(log, "[3/5] Deriving AES-256 key via SHA-256...", "#8EA2FF")
                aes_key = derive_aes_key(secret)
                self._log(log, f"      AES key = {aes_key.hex()[:30]}...", "#5F6F95")
                self._log(log, "[4/5] Downloading encrypted file from server...", "#8EA2FF")
                encrypted = api_download(self.token, file_data["id"])
                self._log(log, f"      Downloaded = {len(encrypted):,} bytes", "#5F6F95")
                self._log(log, "[5/5] Decrypting with AES-256-CTR...", "#8EA2FF")
                original = decrypt_file(encrypted, aes_key)
                self._log(log, f"      Decrypted = {len(original):,} bytes", "#5F6F95")

                detected = "exe" if original[:2] == b"MZ" else "elf" if original[:4] == b"\x7fELF" else "safe"
                needs_warning = (
                    detected in ("exe", "elf")
                    and not filename.endswith(danger_exts())
                    and ".exe" not in filename
                )
                if needs_warning:
                    QMetaObject.invokeMethod(
                        self,
                        "_ask_exec_save",
                        Qt.ConnectionType.QueuedConnection,
                        Q_ARG(object, original),
                        Q_ARG(str, file_data["original_name"]),
                    )
                else:
                    os.makedirs(DL_DIR, exist_ok=True)
                    out = os.path.join(DL_DIR, file_data["original_name"])
                    with open(out, "wb") as f:
                        f.write(original)
                    self._log(log, f"Saved to {out}", "#34D399")
            except Exception as exc:
                self._log(log, f"Error: {exc}", "#F87171")

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(object, str)
    def _ask_exec_save(self, data, name):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Security Warning")
        msg_box.setText(f"{name} appears to be an executable.\nSave anyway?")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setStyleSheet(
            "QMessageBox { background:#FFFFFF; } QLabel { color:#0B1020; font-size:13px; } QPushButton { background:#4F46E5; color:white; border-radius:8px; padding:6px 18px; font-weight:700; min-width:60px; } QPushButton:hover { background:#4338CA; }")
        if msg_box.exec() == QMessageBox.StandardButton.Yes:
            try:
                os.makedirs(DL_DIR, exist_ok=True)
                out = os.path.join(DL_DIR, name)
                with open(out, "wb") as f:
                    f.write(data)
                if alive(self.inbox_log):
                    self._log(self.inbox_log, f"Saved to {out}", "#34D399")
            except Exception as exc:
                if alive(self.inbox_log):
                    self._log(self.inbox_log, f"Error: {exc}", "#F87171")
        else:
            if alive(self.inbox_log):
                self._log(self.inbox_log, "[CANCELLED] Aborted after file signature check.", "#F87171")

    # ---------------------------------------------------------------- CONTACTS
    @pyqtSlot()
    def _show_contacts(self):
        self._set_nav("Contacts")
        scroll, layout = self._scroll_page()
        topbar = QFrame()
        topbar.setObjectName("contacts_topbar")
        topbar.setStyleSheet(
            """
            QFrame#contacts_topbar {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2F3E96,
                    stop:0.52 #4B64DE,
                    stop:1 #3E88F0
                );
                border: 1px solid #3550B3;
                border-radius: 18px;
            }
            """
        )
        add_shadow(topbar, blur=18, y=5, alpha=0.08)
        top_l = QHBoxLayout(topbar)
        top_l.setContentsMargins(18, 16, 18, 16)
        top_l.setSpacing(14)
        top_l.addWidget(IconBox("👥", "#7E92F3", "#FFFFFF", 54, font_px=24))
        top_copy = QVBoxLayout()
        top_copy.setSpacing(5)
        top_title = QLabel("Contacts")
        top_title.setObjectName("contacts_top_title")
        top_title.setStyleSheet(
            "color:#FFFFFF; font-size:24px; font-weight:900; background:transparent; border:none;"
        )
        top_sub = QLabel("You can only send files to people in your contacts list.")
        top_sub.setObjectName("contacts_top_sub")
        top_sub.setStyleSheet(
            "color:rgba(244,248,255,0.92); font-size:13px; background:transparent; border:none;"
        )
        top_copy.addWidget(top_title)
        top_copy.addWidget(top_sub)
        top_l.addLayout(top_copy, 1)
        ref = button("Refresh", "contacts_refresh_btn")
        ref.setFixedWidth(122)
        ref.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,255,255,0.16);
                color: #FFFFFF;
                border: 1px solid rgba(255,255,255,0.32);
                border-radius: 12px;
                font-weight: 800;
                padding: 0 18px;
            }
            QPushButton:hover {
                background: rgba(255,255,255,0.24);
                border: 1px solid rgba(255,255,255,0.46);
            }
            """
        )
        ref.clicked.connect(self._show_contacts)
        top_l.addWidget(ref, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(topbar)
        layout.addSpacing(20)

        add_card = QFrame()
        add_card.setObjectName("contacts_add_card")
        add_card.setStyleSheet(
            """
            QFrame#contacts_add_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #C4D3FF,
                    stop:0.56 #DDE7FF,
                    stop:1 #F0F5FF
                );
                border: 1px solid #9EB6E7;
                border-radius: 18px;
            }
            """
        )
        add_shadow(add_card, blur=22, y=7, alpha=0.10)
        add_v = QVBoxLayout(add_card)
        add_v.setContentsMargins(28, 24, 28, 24)
        add_v.setSpacing(14)
        add_v.addWidget(section_label("Add New Contact"))
        add_row = QHBoxLayout()
        add_row.setSpacing(14)
        self._add_field = field("Enter the username to connect with")
        self._add_field.setObjectName("contacts_field")
        self._add_field.setStyleSheet(
            """
            QLineEdit {
                background: rgba(255,255,255,0.72);
                color: #324766;
                border: 1px solid #8EB0E3;
                border-radius: 13px;
                padding: 0 20px;
                min-height: 50px;
                font-size: 13px;
            }
            QLineEdit:hover {
                background: rgba(255,255,255,0.82);
                border-color: #7096D7;
            }
            QLineEdit:focus {
                background: #FFFFFF;
                border: 2px solid #3766E4;
                padding: 0 19px;
            }
            """
        )
        add_row.addWidget(self._add_field)
        req = button("Send Request", "contacts_send_btn")
        req.setFixedWidth(150)
        req.setStyleSheet(
            """
            QPushButton {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2646A8,
                    stop:0.55 #3E6AE8,
                    stop:1 #3290F6
                );
                color: #FFFFFF;
                border: 1px solid #2452BD;
                border-radius: 13px;
                font-weight: 900;
                min-height: 50px;
                padding: 0 18px;
            }
            QPushButton:hover {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2C4EB6,
                    stop:0.55 #4673EE,
                    stop:1 #3B99FB
                );
            }
            """
        )
        req.clicked.connect(self._send_contact_request)
        add_row.addWidget(req)
        add_v.addLayout(add_row)
        self._contact_msg = label("", "small_muted", wrap=True)
        add_v.addWidget(self._contact_msg)
        layout.addWidget(add_card)
        layout.addSpacing(22)

        results_host = QWidget()
        results_host.setStyleSheet("background:transparent;")
        results_v = QVBoxLayout(results_host)
        results_v.setContentsMargins(0, 0, 0, 0)
        results_v.setSpacing(0)
        loading_card = QFrame()
        loading_card.setObjectName("contacts_network_card")
        loading_card.setStyleSheet(
            """
            QFrame#contacts_network_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #DEE7FF,
                    stop:0.56 #EDF2FF,
                    stop:1 #FAFCFF
                );
                border: 1px solid #B4C6EB;
                border-radius: 18px;
            }
            """
        )
        add_shadow(loading_card, blur=22, y=7, alpha=0.10)
        loading_v = QVBoxLayout(loading_card)
        loading_v.setContentsMargins(34, 30, 34, 30)
        loading_v.setSpacing(10)
        loading_title = QLabel("Loading contacts...")
        loading_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_title.setStyleSheet(
            "color:#101A35; font-size:22px; font-weight:900; background:transparent; border:none;"
        )
        loading_sub = QLabel("Fetching your network and pending requests.")
        loading_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        loading_sub.setStyleSheet(
            "color:#536887; font-size:14px; background:transparent; border:none;"
        )
        loading_v.addWidget(loading_title)
        loading_v.addWidget(loading_sub)
        results_v.addWidget(loading_card)
        layout.addWidget(results_host)
        layout.addStretch()
        self._push(scroll)

        def load_contacts_page():
            pending = []
            contacts = []
            error = ""
            try:
                pending = api_get_requests(self.token)
                contacts = api_get_contacts(self.token)
            except Exception as exc:
                error = str(exc)
            QMetaObject.invokeMethod(
                self,
                "_render_contacts_results",
                Qt.ConnectionType.QueuedConnection,
                Q_ARG(object, results_host),
                Q_ARG(object, pending),
                Q_ARG(object, contacts),
                Q_ARG(str, error),
            )

        threading.Thread(target=load_contacts_page, daemon=True).start()
        return

        try:
            pending = api_get_requests(self.token)
        except Exception:
            pending = []
        if pending:
            pending_card = QFrame()
            pending_card.setObjectName("contacts_pending_card")
            add_shadow(pending_card, blur=22, y=7, alpha=0.10)
            pending_v = QVBoxLayout(pending_card)
            pending_v.setContentsMargins(28, 24, 28, 24)
            pending_v.setSpacing(14)
            pending_v.addWidget(section_label("Incoming Requests"))
            for sender in pending:
                row = PendingRow(sender)
                row.accepted.connect(self._accept_request)
                pending_v.addWidget(row)
            layout.addWidget(pending_card)
            layout.addSpacing(22)

        contacts_card = QFrame()
        contacts_card.setObjectName("contacts_network_card")
        contacts_card.setStyleSheet(
            """
            QFrame#contacts_network_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #DEE7FF,
                    stop:0.56 #EDF2FF,
                    stop:1 #FAFCFF
                );
                border: 1px solid #B4C6EB;
                border-radius: 18px;
            }
            """
        )
        add_shadow(contacts_card, blur=22, y=7, alpha=0.10)
        contacts_v = QVBoxLayout(contacts_card)
        contacts_v.setContentsMargins(28, 24, 28, 24)
        contacts_v.setSpacing(14)
        try:
            contacts = api_get_contacts(self.token)
        except Exception:
            contacts = []

        head = QHBoxLayout()
        head.addWidget(section_label("Your Network"))
        if contacts:
            count = QLabel(str(len(contacts)))
            count.setStyleSheet(
                f"background:{C['green_soft']}; color:{C['green']}; border-radius:10px; "
                "padding:3px 11px; font-weight:900;"
            )
            head.addWidget(count)
        head.addStretch()
        contacts_v.addLayout(head)

        if contacts:
            for contact in contacts:
                pub = str(contact["dh_public_key"])
                short = pub[:14] + "..." + pub[-8:] if len(pub) > 28 else pub
                contacts_v.addWidget(ContactRow(contact["username"], short))
        else:
            empty_wrap = QWidget()
            ew = QVBoxLayout(empty_wrap)
            ew.setContentsMargins(0, 18, 0, 10)
            ew.setSpacing(10)
            ew.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_icon = IconBox("👥", "#E7EEFF", "#355FD5", 76, font_px=34)
            e_t = QLabel("No contacts yet")
            e_t.setObjectName("contacts_empty_title")
            e_t.setStyleSheet(
                "color:#101A35; font-size:22px; font-weight:900; background:transparent; border:none;"
            )
            e_s = QLabel("Send a request to get started.")
            e_s.setObjectName("contacts_empty_sub")
            e_s.setStyleSheet(
                "color:#536887; font-size:14px; background:transparent; border:none;"
            )
            e_t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ew.addWidget(e_icon)
            ew.addWidget(e_t)
            ew.addWidget(e_s)
            contacts_v.addWidget(empty_wrap)
        layout.addWidget(contacts_card)
        layout.addStretch()
        self._push(scroll)

    @pyqtSlot(object, object, object, str)
    def _render_contacts_results(self, host, pending, contacts, error):
        if not alive(host):
            return
        host_layout = host.layout()
        clear_layout(host_layout)
        host_layout.setSpacing(0)

        if error:
            host_layout.addWidget(label(f"Error loading contacts: {error}", "error_label", wrap=True))
            return

        if pending:
            pending_card = QFrame()
            pending_card.setObjectName("contacts_pending_card")
            add_shadow(pending_card, blur=22, y=7, alpha=0.10)
            pending_v = QVBoxLayout(pending_card)
            pending_v.setContentsMargins(28, 24, 28, 24)
            pending_v.setSpacing(14)
            pending_v.addWidget(section_label("Incoming Requests"))
            for sender in pending:
                row = PendingRow(sender)
                row.accepted.connect(self._accept_request)
                pending_v.addWidget(row)
            host_layout.addWidget(pending_card)
            host_layout.addSpacing(22)

        contacts_card = QFrame()
        contacts_card.setObjectName("contacts_network_card")
        contacts_card.setStyleSheet(
            """
            QFrame#contacts_network_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #DEE7FF,
                    stop:0.56 #EDF2FF,
                    stop:1 #FAFCFF
                );
                border: 1px solid #B4C6EB;
                border-radius: 18px;
            }
            """
        )
        add_shadow(contacts_card, blur=22, y=7, alpha=0.10)
        contacts_v = QVBoxLayout(contacts_card)
        contacts_v.setContentsMargins(28, 24, 28, 24)
        contacts_v.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(section_label("Your Network"))
        if contacts:
            count = QLabel(str(len(contacts)))
            count.setStyleSheet(
                f"background:{C['green_soft']}; color:{C['green']}; border-radius:10px; "
                "padding:3px 11px; font-weight:900;"
            )
            head.addWidget(count)
        head.addStretch()
        contacts_v.addLayout(head)

        if contacts:
            for contact in contacts:
                pub = str(contact["dh_public_key"])
                short = pub[:14] + "..." + pub[-8:] if len(pub) > 28 else pub
                contacts_v.addWidget(ContactRow(contact["username"], short))
        else:
            empty_wrap = QWidget()
            ew = QVBoxLayout(empty_wrap)
            ew.setContentsMargins(0, 18, 0, 10)
            ew.setSpacing(10)
            ew.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_icon = IconBox("👥", "#E7EEFF", "#355FD5", 76, font_px=34)
            ew.addWidget(e_icon, alignment=Qt.AlignmentFlag.AlignCenter)
            e_t = QLabel("No contacts yet")
            e_s = QLabel("Send a request to get started.")
            e_t.setStyleSheet(
                "color:#101A35; font-size:22px; font-weight:900; background:transparent; border:none;"
            )
            e_s.setStyleSheet(
                "color:#536887; font-size:14px; background:transparent; border:none;"
            )
            e_t.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ew.addWidget(e_t)
            ew.addWidget(e_s)
            contacts_v.addWidget(empty_wrap)
        host_layout.addWidget(contacts_card)

    def _send_contact_request(self):
        target = self._add_field.text().strip().lower()
        if not target:
            self._contact_msg.setObjectName("error_label")
            self._contact_msg.setText("Please enter a username.")
            polish(self._contact_msg)
            return

        def run():
            try:
                msg = api_send_request(self.token, target)
                QMetaObject.invokeMethod(
                    self,
                    "_set_contact_msg",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, msg),
                    Q_ARG(bool, True),
                )
            except Exception as exc:
                QMetaObject.invokeMethod(
                    self,
                    "_set_contact_msg",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, str(exc)),
                    Q_ARG(bool, False),
                )

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(str, bool)
    def _set_contact_msg(self, msg, ok):
        if not alive(self._contact_msg):
            return
        self._contact_msg.setObjectName("success_label" if ok else "error_label")
        self._contact_msg.setText(msg)
        polish(self._contact_msg)

    def _accept_request(self, sender):
        def run():
            try:
                api_accept_request(self.token, sender)
                QMetaObject.invokeMethod(self, "_show_contacts", Qt.ConnectionType.QueuedConnection)
            except Exception as exc:
                QMetaObject.invokeMethod(
                    self,
                    "_err_dialog",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, str(exc)),
                )

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(str)
    def _err_dialog(self, msg):
        QMessageBox.critical(self, "Error", msg)

    # -------------------------------------------------------------------- LOGS
    @pyqtSlot()
    def _show_logs(self):
        self._set_nav("Audit Logs")
        scroll, layout = self._scroll_page()

        topbar = QFrame()
        topbar.setObjectName("logs_topbar")
        topbar.setStyleSheet(
            """
            QFrame#logs_topbar {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2D3D95,
                    stop:0.52 #4862DE,
                    stop:1 #3E86F0
                );
                border: 1px solid #3551B4;
                border-radius: 18px;
            }
            """
        )
        add_shadow(topbar, blur=18, y=5, alpha=0.08)
        top_l = QHBoxLayout(topbar)
        top_l.setContentsMargins(18, 16, 18, 16)
        top_l.setSpacing(14)
        top_l.addWidget(IconBox("📋", "rgba(255,255,255,0.18)", "#FFFFFF", 54, font_px=23))
        top_copy = QVBoxLayout()
        top_copy.setSpacing(5)
        top_title = QLabel("Audit Logs")
        top_title.setObjectName("logs_top_title")
        top_title.setStyleSheet(
            "color:#FFFFFF; font-size:24px; font-weight:900; background:transparent; border:none;"
        )
        top_sub = QLabel("Complete activity history. File contents are never logged.")
        top_sub.setObjectName("logs_top_sub")
        top_sub.setStyleSheet(
            "color:rgba(244,248,255,0.92); font-size:13px; background:transparent; border:none;"
        )
        top_copy.addWidget(top_title)
        top_copy.addWidget(top_sub)
        top_l.addLayout(top_copy, 1)
        ref = button("Refresh", "logs_refresh_btn")
        ref.setFixedWidth(122)
        ref.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,255,255,0.16);
                color: #FFFFFF;
                border: 1px solid rgba(255,255,255,0.32);
                border-radius: 12px;
                font-weight: 800;
                padding: 0 18px;
            }
            QPushButton:hover {
                background: rgba(255,255,255,0.24);
                border: 1px solid rgba(255,255,255,0.46);
            }
            """
        )
        ref.clicked.connect(self._show_logs)
        top_l.addWidget(ref, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(topbar)
        layout.addSpacing(20)

        log_card = QFrame()
        log_card.setObjectName("logs_activity_card")
        log_card.setStyleSheet(
            """
            QFrame#logs_activity_card {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #D7E1FF,
                    stop:0.56 #E8EEFF,
                    stop:1 #F8FAFF
                );
                border: 1px solid #AEC0E8;
                border-radius: 18px;
            }
            """
        )
        add_shadow(log_card, blur=22, y=7, alpha=0.10)
        log_v = QVBoxLayout(log_card)
        log_v.setContentsMargins(28, 24, 28, 24)
        log_v.setSpacing(14)
        head = QHBoxLayout()
        head.addWidget(IconBox("🧾", "#BFD2FB", "#2346AA", 40, font_px=18))
        head.addWidget(section_label("Activity Log"))
        head.addStretch()
        badge = QLabel("Tamper-evident")
        badge.setStyleSheet(
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #AFC6FF, stop:1 #D8E4FF); "
            "color:#1E57D7; border-radius:10px; border:1px solid #8EAFEF; padding:4px 12px; font-weight:900;"
        )
        head.addWidget(badge)
        log_v.addLayout(head)

        box = QTextEdit()
        box.setObjectName("logs_console")
        box.setReadOnly(True)
        box.setStyleSheet(
            "background:#0B1123; color:#C9D5F7; border:1px solid #1F2B4B; "
            "border-radius:14px; padding:16px; font-family:'Cascadia Code',Consolas,monospace; font-size:12px;"
        )
        box.setHtml(
            '<span style="color:#8EA2FF; font-family:Cascadia Code, Consolas, monospace; font-size:12px;">'
            "Loading activity..."
            "</span>"
        )
        log_v.addWidget(box)
        layout.addWidget(log_card, stretch=1)
        self._push(scroll)

        colors = {
            "REGISTER": "#34D399",
            "LOGIN": "#8EA2FF",
            "LOGIN_FAILED": "#F87171",
            "FILE_UPLOAD": "#FBBF24",
            "FILE_DOWNLOAD": "#60A5FA",
            "CONTACT_REQUEST_SENT": "#C084FC",
            "CONTACT_REQUEST_RECEIVED": "#A78BFA",
            "CONTACT_ACCEPTED": "#34D399",
            "UPLOAD_BLOCKED": "#F87171",
            "LOGOUT": "#6B7280",
        }

        def load():
            try:
                logs = api_get_logs(self.token)
                QMetaObject.invokeMethod(
                    self,
                    "_fill_logs",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(object, logs),
                    Q_ARG(object, box),
                    Q_ARG(object, colors),
                )
            except Exception as exc:
                self._log(box, f"Error: {exc}", "#F87171")

        threading.Thread(target=load, daemon=True).start()

    @pyqtSlot(object, object, object)
    def _fill_logs(self, logs, box, colors):
        if not alive(box):
            return
        if not logs:
            box.setHtml(
                '<span style="color:#6B7280; font-family:Cascadia Code, Consolas, monospace; font-size:12px;">'
                "No activity recorded yet."
                "</span>"
            )
            return
        lines = []
        for entry in reversed(logs):
            ts = entry.get("timestamp", "")
            action = entry.get("action", "")
            detail = entry.get("detail", "")
            ip = entry.get("ip", "")
            color = colors.get(action, "#C8D2F0")
            lines.append(
                f'<span style="color:{color}; font-family:Cascadia Code, Consolas, monospace; font-size:12px;">'
                f"{escape(f'[{ts}]  {action}')}"
                "</span><br>"
            )
            lines.append(
                '<span style="color:#5F6F95; font-family:Cascadia Code, Consolas, monospace; font-size:12px;">'
                f"{escape(f'           {detail}  |  IP: {ip}')}"
                "</span><br><br>"
            )
        box.setHtml("".join(lines))


if __name__ == "__main__":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("secureshare.v4")
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    font = QFont("Segoe UI", 10)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    app.setFont(font)
    window = App()
    window.show()
    sys.exit(app.exec())
