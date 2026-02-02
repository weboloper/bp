"""
SMTP Email Provider - Django's built-in email backend

Uses Django's email sending functionality with custom SMTP configuration.
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional

from .base import BaseEmailProvider, EmailResult, EmailStatus

logger = logging.getLogger(__name__)


class SMTPProvider(BaseEmailProvider):
    """
    SMTP Email Provider implementation.

    Uses direct SMTP connection for sending emails.
    Supports both plain text and HTML emails.
    """

    @property
    def provider_name(self) -> str:
        return 'smtp'

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        default_from: Optional[str] = None,
        default_from_name: Optional[str] = None
    ):
        """
        Initialize SMTP provider.

        Args:
            host: SMTP server hostname
            port: SMTP server port
            username: SMTP authentication username
            password: SMTP authentication password
            use_tls: Whether to use TLS encryption
            default_from: Default from email address
            default_from_name: Default from name
        """
        self.host = host or 'localhost'
        self.port = port or (587 if use_tls else 25)
        self.username = username or ''
        self.password = password or ''
        self.use_tls = use_tls
        self.default_from = default_from or ''
        self.default_from_name = default_from_name or ''
        self.timeout = 30

    def _format_address(self, email: str, name: Optional[str] = None) -> str:
        """Format email address with optional name."""
        if name:
            return f"{name} <{email}>"
        return email

    def _create_message(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None
    ) -> MIMEMultipart:
        """Create MIME message."""
        msg = MIMEMultipart('alternative')

        # Headers
        sender = from_email or self.default_from
        sender_name = from_name or self.default_from_name
        msg['From'] = self._format_address(sender, sender_name)
        msg['To'] = to_email
        msg['Subject'] = subject

        if reply_to:
            msg['Reply-To'] = reply_to

        # Body
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        if body_html:
            msg.attach(MIMEText(body_html, 'html', 'utf-8'))

        return msg

    def send(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None
    ) -> EmailResult:
        """
        Send a single email via SMTP.
        """
        if not self.validate_email(to_email):
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='INVALID_EMAIL',
                error_message='Geçersiz email adresi'
            )

        sender = from_email or self.default_from
        if not sender:
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='NO_SENDER',
                error_message='Gönderici email adresi belirtilmedi'
            )

        msg = self._create_message(
            to_email=to_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            from_email=from_email,
            from_name=from_name,
            reply_to=reply_to
        )

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                if self.use_tls:
                    server.starttls()

                if self.username and self.password:
                    server.login(self.username, self.password)

                server.send_message(msg)

            logger.info(f"Email sent successfully to {to_email}")
            return EmailResult(
                success=True,
                status=EmailStatus.SENT,
                raw_response={'to': to_email, 'subject': subject}
            )

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication error: {e}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='AUTH_ERROR',
                error_message=f'SMTP kimlik doğrulama hatası: {str(e)}'
            )
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"Recipients refused: {e}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='RECIPIENTS_REFUSED',
                error_message=f'Alıcı reddedildi: {str(e)}'
            )
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='SMTP_ERROR',
                error_message=f'SMTP hatası: {str(e)}'
            )
        except Exception as e:
            logger.exception(f"Unexpected error sending email: {e}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='UNKNOWN_ERROR',
                error_message=str(e)
            )

    def send_bulk(
        self,
        recipients: List[Dict[str, str]],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> List[EmailResult]:
        """
        Send email to multiple recipients via SMTP.

        Args:
            recipients: List of dicts with 'email' and optionally 'name'
            subject: Email subject
            body_text: Plain text body
            body_html: Optional HTML body

        Returns:
            List of EmailResult for each recipient
        """
        results = []

        for recipient in recipients:
            email = recipient.get('email', '')
            name = recipient.get('name', '')

            if not email:
                results.append(EmailResult(
                    success=False,
                    status=EmailStatus.FAILED,
                    error_code='NO_EMAIL',
                    error_message='Email adresi belirtilmedi'
                ))
                continue

            result = self.send(
                to_email=email,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )
            results.append(result)

        return results
