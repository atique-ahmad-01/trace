"""Outgoing email over SMTP (stdlib only). Works with any provider that offers SMTP: Resend, SendGrid, SES, Gmail."""

import asyncio
import smtplib
import ssl
from email.message import EmailMessage

from loguru import logger

from app.core.config import settings


def _send_sync(to: str, subject: str, text: str, html: str | None) -> None:
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USERNAME or f"no-reply@{settings.APP_NAME.lower()}.local"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    security = settings.SMTP_SECURITY.lower()
    context = ssl.create_default_context()
    if security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.SMTP_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.SMTP_TIMEOUT)
    with server:
        if security == "starttls":
            server.starttls(context=context)
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(msg)


async def send_email(to: str, subject: str, text: str, html: str | None = None) -> bool:
    """Returns True when the message was handed to the SMTP server. Never raises."""
    if not settings.email_delivery_configured:
        return False
    try:
        await asyncio.to_thread(_send_sync, to, subject, text, html)
        return True
    except Exception:  # noqa: BLE001
        logger.exception(f"Sending email to {to} failed")
        return False


async def send_verification_email(to: str, link: str) -> bool:
    hours = settings.EMAIL_VERIFICATION_EXPIRE_HOURS
    text = (
        f"Welcome to {settings.APP_NAME}!\n\n"
        f"Confirm your email address to activate your account:\n{link}\n\n"
        f"The link expires in {hours} hours. If you did not create an account, ignore this email."
    )
    html = (
        f"<p>Welcome to {settings.APP_NAME}!</p>"
        f"<p>Confirm your email address to activate your account:</p>"
        f'<p><a href="{link}" style="display:inline-block;padding:10px 18px;background:#0891b2;color:#fff;'
        f'border-radius:6px;text-decoration:none">Verify email</a></p>'
        f'<p style="color:#666;font-size:12px">Or open this link: {link}<br>'
        f"It expires in {hours} hours. If you did not create an account, ignore this email.</p>"
    )
    return await send_email(to, f"Verify your {settings.APP_NAME} account", text, html)
