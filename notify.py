import os
import smtplib
from email.message import EmailMessage
import threading

# Try Twilio import (optional)
try:
    from twilio.rest import Client as TwilioClient
    _twilio_installed = True
except Exception:
    _twilio_installed = False

def send_email(subject, body, to_addrs):
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))

    if not smtp_user or not smtp_pass:
        print("Email credentials missing (SMTP_USER/SMTP_PASS). Skipping email.")
        return False

    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print("Email sent to:", to_addrs)
        return True
    except Exception as e:
        print("Failed to send email:", repr(e))
        return False

def send_sms(body, to_number):
    if not _twilio_installed:
        print("Twilio not installed; install with pip install twilio to enable SMS.")
        return False

    tw_sid = os.getenv("TWILIO_SID")
    tw_token = os.getenv("TWILIO_TOKEN")
    tw_from = os.getenv("TWILIO_FROM")

    if not (tw_sid and tw_token and tw_from):
        print("Twilio credentials missing; skipping SMS.")
        return False

    try:
        client = TwilioClient(tw_sid, tw_token)
        msg = client.messages.create(body=body, from_=tw_from, to=to_number)
        print("SMS sent, sid:", getattr(msg, 'sid', None))
        return True
    except Exception as e:
        print("Failed to send SMS:", repr(e))
        return False

def notify_async(subject, body, email_to=None, sms_to=None):
    def _job():
        if email_to:
            send_email(subject, body, email_to)
        if sms_to:
            send_sms(body, sms_to)
    t = threading.Thread(target=_job, daemon=True)
    t.start()
    return t
