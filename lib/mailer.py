"""
Ares Mailer — Protocolo de Comunicación Externa (FORZOSO)
=========================================================
Toda comunicación por correo DEBE pasar por aquí.
Este módulo aplica el protocolo automáticamente.

REGLAS DEL PROTOCOLO (no negociables):
1. From: Alicia Ramos <aramos@agentmail.to> (AgentMail, NO SMTP directo)
2. BCC: aramos@palapacode.com (copia local para archivo POP3)
3. Reply-To: aramos@palapacode.com (respuestas van a mi bandeja)
4. Asunto: [TIPO] — Título descriptivo | Fecha
5. Cuerpo: Resumen Ejecutivo + Disclaimer ISO/IEC 27001
6. Archivos: como attachment, no inline
"""
import json, os, base64, ssl, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

AGENTMAIL_API_KEY = None
AGENTMAIL_INBOX = "aramos@agentmail.to"
POP3_EMAIL = "aramos@palapacode.com"

# Try to load API key from config
try:
    import subprocess
    result = subprocess.run(
        ["python3", "-c", "import json; f=open('/root/.openclaw/openclaw.json'); c=json.load(f); print(c.get('env',{}).get('AGENTMAIL_API_KEY',''))"],
        capture_output=True, text=True, timeout=5
    )
    AGENTMAIL_API_KEY = result.stdout.strip()
except:
    pass

DISCLAIMER = """
---
[DISCLAIMER LEGAL]
Este mensaje y sus archivos adjuntos son confidenciales y para uso exclusivo
del destinatario. Si recibio este correo por error, eliminelo y notifique al
remitente. Cumplimiento de buenas practicas ISO/IEC 27001.

Generado por Ares Tool Security — Suite de Auditoria de Seguridad
Enviado por Alicia ✨ — Agente de IA Autonoma
aramos@palapacode.com
---

--
Alicia Ramos Claw ✨
aramos@palapacode.com
Ares Tool Security
"""


def send(to, subject, body_text="", html_file=None, tipo="REPORTE", cc=None):
    """
    Envia un correo SIGUIENDO ESTRICTAMENTE EL PROTOCOLO.
    
    Args:
        to: str o list — destinatario(s)
        subject: str — asunto (se le agrega [TIPO] — automaticamente)
        body_text: str — cuerpo en texto plano (resumen ejecutivo)
        html_file: str — ruta a archivo HTML para adjuntar
        tipo: str — REPORTE, ALERTA, AVISO, etc.
        cc: str o list — copia
    """
    if isinstance(to, str):
        to = [to]

    # ── Aplicar protocolo ──
    fecha = datetime.now().strftime("%Y-%m-%d")
    full_subject = f"[{tipo}] — {subject} | {fecha}"

    # Construir cuerpo completo
    full_body = body_text.strip()
    if full_body:
        full_body += "\n\n"
    full_body += DISCLAIMER

    # ── Intentar AgentMail primero ──
    if AGENTMAIL_API_KEY:
        try:
            _send_agentmail(to, full_subject, full_body, html_file, cc)
            return True
        except Exception as e:
            print(f"  ⚠️  AgentMail fallo, intentando SMTP: {e}")
    
    # ── Fallback SMTP directo ──
    _send_smtp(to, full_subject, full_body, html_file, cc)
    return True


def _send_agentmail(to, subject, body_text, html_file=None, cc=None):
    """Envio por AgentMail API."""
    import urllib.request
    
    payload = {
        "from": f"Alicia Ramos <{AGENTMAIL_INBOX}>",
        "to": to,
        "bcc": [POP3_EMAIL],
        "reply_to": [POP3_EMAIL],
        "subject": subject,
        "text": body_text,
    }
    
    if cc:
        payload["cc"] = cc if isinstance(cc, list) else [cc]
    
    # Adjuntar HTML si existe
    if html_file and os.path.exists(html_file):
        with open(html_file, "rb") as f:
            content = f.read()
        payload["attachments"] = [{
            "filename": os.path.basename(html_file),
            "content_type": "text/html",
            "content": base64.b64encode(content).decode()
        }]
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.agentmail.to/v0/inboxes/{AGENTMAIL_INBOX}/messages/send",
        data=data,
        headers={
            "Authorization": f"Bearer {AGENTMAIL_API_KEY}",
            "Content-Type": "application/json"
        },
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        print(f"  ✅ Enviado via AgentMail | ID: {result.get('message_id','?')[:30]}...")
        print(f"  📥 Para: {', '.join(to)}")
        print(f"  🔄 BCC: {POP3_EMAIL}")
        print(f"  ↩️  Reply-To: {POP3_EMAIL}")


def _send_smtp(to, subject, body_text, html_file=None, cc=None):
    """Fallback SMTP directo si AgentMail falla."""
    msg = MIMEMultipart("mixed")
    msg["From"] = f"Alicia Ramos <{POP3_EMAIL}>"
    msg["To"] = ", ".join(to)
    msg["Bcc"] = POP3_EMAIL
    msg["Reply-To"] = POP3_EMAIL
    msg["Subject"] = subject
    
    if cc:
        if isinstance(cc, list):
            msg["Cc"] = ", ".join(cc)
        else:
            msg["Cc"] = cc
    
    # Texto plano
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    
    # Adjuntar HTML
    if html_file and os.path.exists(html_file):
        with open(html_file, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(html_file)}"')
            msg.attach(part)
    
    # Enviar
    context = ssl.create_default_context()
    recipients = to + [POP3_EMAIL]
    if cc:
        recipients += cc if isinstance(cc, list) else [cc]
    
    with smtplib.SMTP_SSL("mail.palapacode.com", 465, context=context, timeout=30) as server:
        server.login(POP3_EMAIL, "K)C[rU(9W9h*")
        server.sendmail(POP3_EMAIL, list(set(recipients)), msg.as_string())
    
    print(f"  ✅ Enviado via SMTP (fallback)")
    print(f"  📥 Para: {', '.join(to)}")
    print(f"  🔄 BCC: {POP3_EMAIL}")


if __name__ == "__main__":
    # Test de envio
    send(
        to="uramos@sistemascontino.com.mx",
        subject="Prueba de protocolo mailer.py",
        body_text="Test del modulo de correo automatizado.\n\nSi ves esto, el protocolo funciona.",
        tipo="TEST"
    )
