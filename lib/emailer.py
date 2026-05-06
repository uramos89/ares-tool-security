#!/usr/bin/env python3
"""Email Module — Send Ares Tool Security reports via SMTP (SSL)"""
import os, sys, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

# Load credentials from secure file
def _load_creds():
    env_file = os.path.expanduser("~/.openclaw/secrets/email.env")
    creds = {}
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    creds[k] = v
    return creds

CREDS = _load_creds()
DISPLAY_NAME = "Alicia Ramos"

SIGNATURE = """
—
Enviado por Alicia ✨ — Agente de IA Autónoma
Especialista en: Seguridad, auditoría y desarrollo de software

🔐 Ares Tool Security — Suite de auditoría
⚠️ Este mensaje es generado por un sistema automatizado de IA.
El contenido es auditable, verificable y puede ser utilizado
como evidencia en procesos de cumplimiento normativo.
© 2026 — Todos los derechos reservados.
"""

def send_report(report_path: str, to_email: str = None, subject: str = None) -> bool:
    """Send a Ares Tool Security report via email"""
    report_path = Path(report_path)
    if not report_path.exists():
        print(f"❌ Report not found: {report_path}")
        return False

    smtp_server = CREDS.get("SMTP_SERVER", "mail.palapacode.com")
    smtp_port = int(CREDS.get("SMTP_PORT", 465))
    username = CREDS.get("SMTP_USERNAME", "")
    password = CREDS.get("SMTP_PASSWORD", "")
    from_email = CREDS.get("FROM_EMAIL", username)

    if not to_email:
        to_email = input("  Send to email: ")

    if not subject:
        subject = f"🔐 Ares Tool Security Report — {report_path.name}"

    # Read report content
    with open(report_path) as f:
        report_content = f.read()

    # Build email
    msg = MIMEMultipart()
    msg["From"] = f"{DISPLAY_NAME} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    # Attach report as body
    msg.attach(MIMEText(report_content + "\n\n" + SIGNATURE, "plain", "utf-8"))

    # Attach report file
    with open(report_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={report_path.name}")
        msg.attach(part)

    # Send via SMTP SSL
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=30) as server:
            server.login(username, password)
            server.sendmail(from_email, to_email, msg.as_string())
        print(f"  ✅ Report sent to {to_email}")
        return True
    except Exception as e:
        print(f"  ❌ Failed to send: {e}")
        return False

def send_quick(subject: str, body: str, to_email: str = None) -> bool:
    """Send a quick email without attachments"""
    if not to_email:
        to_email = input("  Send to email: ")

    smtp_server = CREDS.get("SMTP_SERVER", "mail.palapacode.com")
    smtp_port = int(CREDS.get("SMTP_PORT", 465))
    username = CREDS.get("SMTP_USERNAME", "")
    password = CREDS.get("SMTP_PASSWORD", "")
    from_email = CREDS.get("FROM_EMAIL", username)

    msg = MIMEText(body + "\n\n" + SIGNATURE, "plain", "utf-8")
    msg["From"] = f"{DISPLAY_NAME} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=30) as server:
            server.login(username, password)
            server.sendmail(from_email, to_email, msg.as_string())
        print(f"  ✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        send_report(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print("  Usage: python3 lib/emailer.py <report.md> [to@email.com]")
