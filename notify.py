import os
import smtplib
from email.message import EmailMessage
import threading
import logging

# Set up logging
logger = logging.getLogger(__name__)

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
    """SMS notification function (disabled)"""
    logger.warning("SMS notifications are currently disabled.")
    return False

def notify_async(notification_type, *args, **kwargs):
    """Send notification asynchronously in a separate thread."""
    def _send():
        try:
            if notification_type == 'email':
                send_email(*args, **kwargs)
            elif notification_type == 'sms':
                logger.warning("SMS notifications are currently disabled.")
        except Exception as e:
            logger.error(f"Error sending {notification_type} notification: {str(e)}")
    
    thread = threading.Thread(target=_send)
    thread.daemon = True
    thread.start()
    return thread
