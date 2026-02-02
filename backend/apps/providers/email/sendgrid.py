"""
SendGrid Email Provider - Cloud-based email service

API Documentation: https://docs.sendgrid.com/api-reference/mail-send/mail-send
"""
import logging
from typing import List, Dict, Optional, Any

import requests

from .base import BaseEmailProvider, EmailResult, EmailStatus

logger = logging.getLogger(__name__)


class SendgridProvider(BaseEmailProvider):
    """
    SendGrid Email Provider implementation.

    Uses SendGrid Web API v3 for sending emails.
    Supports single and bulk email sending.
    """

    @property
    def provider_name(self) -> str:
        return 'sendgrid'

    BASE_URL = "https://api.sendgrid.com/v3"
    SEND_URL = f"{BASE_URL}/mail/send"

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_from: Optional[str] = None,
        default_from_name: Optional[str] = None
    ):
        """
        Initialize SendGrid provider.

        Args:
            api_key: SendGrid API key
            default_from: Default from email address
            default_from_name: Default from name
        """
        self.api_key = api_key or ''
        self.default_from = default_from or ''
        self.default_from_name = default_from_name or ''
        self.timeout = 30

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for SendGrid API."""
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

    def _build_payload(
        self,
        to_email: str,
        to_name: Optional[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """Build SendGrid API payload."""
        sender = from_email or self.default_from
        sender_name = from_name or self.default_from_name

        payload = {
            'personalizations': [{
                'to': [{'email': to_email}]
            }],
            'from': {
                'email': sender
            },
            'subject': subject,
            'content': []
        }

        # Add sender name if provided
        if sender_name:
            payload['from']['name'] = sender_name

        # Add recipient name if provided
        if to_name:
            payload['personalizations'][0]['to'][0]['name'] = to_name

        # Add reply-to if provided
        if reply_to:
            payload['reply_to'] = {'email': reply_to}

        # Add content
        payload['content'].append({
            'type': 'text/plain',
            'value': body_text
        })

        if body_html:
            payload['content'].append({
                'type': 'text/html',
                'value': body_html
            })

        return payload

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
        Send a single email via SendGrid.
        """
        if not self.validate_email(to_email):
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='INVALID_EMAIL',
                error_message='Geçersiz email adresi'
            )

        if not self.api_key:
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='NO_API_KEY',
                error_message='SendGrid API key belirtilmedi'
            )

        sender = from_email or self.default_from
        if not sender:
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='NO_SENDER',
                error_message='Gönderici email adresi belirtilmedi'
            )

        payload = self._build_payload(
            to_email=to_email,
            to_name=None,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            from_email=from_email,
            from_name=from_name,
            reply_to=reply_to
        )

        try:
            response = requests.post(
                self.SEND_URL,
                json=payload,
                headers=self._get_headers(),
                timeout=self.timeout
            )

            # SendGrid returns 202 Accepted for successful sends
            if response.status_code == 202:
                message_id = response.headers.get('X-Message-Id', '')
                logger.info(f"Email sent via SendGrid to {to_email}, ID: {message_id}")
                return EmailResult(
                    success=True,
                    message_id=message_id,
                    status=EmailStatus.SENT,
                    raw_response={'status_code': response.status_code}
                )
            else:
                error_body = response.json() if response.text else {}
                errors = error_body.get('errors', [])
                error_msg = errors[0].get('message', 'Bilinmeyen hata') if errors else response.text

                logger.error(f"SendGrid error: {response.status_code} - {error_msg}")
                return EmailResult(
                    success=False,
                    status=EmailStatus.FAILED,
                    error_code=str(response.status_code),
                    error_message=error_msg,
                    raw_response=error_body
                )

        except requests.RequestException as e:
            logger.exception(f"SendGrid API error: {e}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='API_ERROR',
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
        Send email to multiple recipients via SendGrid.

        Note: SendGrid supports up to 1000 recipients per request using personalizations,
        but for simplicity and individual tracking, we send separately.

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

            # Build payload with recipient name
            payload = self._build_payload(
                to_email=email,
                to_name=name if name else None,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )

            try:
                response = requests.post(
                    self.SEND_URL,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.timeout
                )

                if response.status_code == 202:
                    message_id = response.headers.get('X-Message-Id', '')
                    results.append(EmailResult(
                        success=True,
                        message_id=message_id,
                        status=EmailStatus.SENT,
                        raw_response={'status_code': response.status_code}
                    ))
                else:
                    error_body = response.json() if response.text else {}
                    errors = error_body.get('errors', [])
                    error_msg = errors[0].get('message', 'Bilinmeyen hata') if errors else response.text

                    results.append(EmailResult(
                        success=False,
                        status=EmailStatus.FAILED,
                        error_code=str(response.status_code),
                        error_message=error_msg,
                        raw_response=error_body
                    ))

            except requests.RequestException as e:
                results.append(EmailResult(
                    success=False,
                    status=EmailStatus.FAILED,
                    error_code='API_ERROR',
                    error_message=str(e)
                ))

        return results
