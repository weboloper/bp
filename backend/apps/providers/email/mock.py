"""
Mock Email Provider - For testing and development

Simulates email sending without actually sending emails.
Stores sent emails in memory for verification in tests.
"""
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, ClassVar

from .base import BaseEmailProvider, EmailResult, EmailStatus

logger = logging.getLogger(__name__)


@dataclass
class MockEmail:
    """Represents a mock email for testing."""
    id: str
    to_email: str
    to_name: Optional[str]
    from_email: str
    from_name: Optional[str]
    reply_to: Optional[str]
    subject: str
    body_text: str
    body_html: Optional[str]
    sent_at: datetime
    status: EmailStatus = EmailStatus.SENT


class MockEmailProvider(BaseEmailProvider):
    """
    Mock Email Provider for testing and development.

    Features:
    - Stores all sent emails in memory
    - Configurable failure simulation
    - Helper methods for test assertions
    """

    @property
    def provider_name(self) -> str:
        return 'mock'

    # Class-level storage for all mock emails
    _sent_emails: ClassVar[List[MockEmail]] = []
    _fail_next: ClassVar[bool] = False
    _fail_emails: ClassVar[List[str]] = []  # Specific emails that should fail
    _simulate_delay: ClassVar[bool] = False

    def __init__(
        self,
        default_from: Optional[str] = None,
        default_from_name: Optional[str] = None
    ):
        """
        Initialize Mock Email provider.

        Args:
            default_from: Default from email address
            default_from_name: Default from name
        """
        self.default_from = default_from or 'test@salon.local'
        self.default_from_name = default_from_name or 'Test Salon'

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
        Simulate sending an email.
        """
        if not self.validate_email(to_email):
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='INVALID_EMAIL',
                error_message='Geçersiz email adresi'
            )

        # Check if we should simulate a failure
        if self._fail_next or to_email in self._fail_emails:
            self._fail_next = False
            logger.info(f"[MOCK] Simulated email failure to {to_email}")
            return EmailResult(
                success=False,
                status=EmailStatus.FAILED,
                error_code='SIMULATED_FAILURE',
                error_message='Simulated email sending failure'
            )

        # Generate mock message ID
        message_id = f"mock_{uuid.uuid4().hex[:16]}"

        # Create and store mock email
        mock_email = MockEmail(
            id=message_id,
            to_email=to_email,
            to_name=None,
            from_email=from_email or self.default_from,
            from_name=from_name or self.default_from_name,
            reply_to=reply_to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            sent_at=datetime.now()
        )
        self._sent_emails.append(mock_email)

        logger.info(f"[MOCK] Email 'sent' to {to_email}: {subject}")
        return EmailResult(
            success=True,
            message_id=message_id,
            status=EmailStatus.SENT,
            raw_response={
                'mock': True,
                'to': to_email,
                'subject': subject
            }
        )

    def send_bulk(
        self,
        recipients: List[Dict[str, str]],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None
    ) -> List[EmailResult]:
        """
        Simulate sending email to multiple recipients.
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

            # For bulk, we store the name as well
            result = self.send(
                to_email=email,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )

            # Update the mock email with recipient name
            if result.success and name:
                for mock_email in reversed(self._sent_emails):
                    if mock_email.id == result.message_id:
                        mock_email.to_name = name
                        break

            results.append(result)

        return results

    # ==================== Testing Helpers ====================

    @classmethod
    def get_sent_emails(cls) -> List[MockEmail]:
        """Get all sent mock emails."""
        return cls._sent_emails.copy()

    @classmethod
    def get_last_email(cls) -> Optional[MockEmail]:
        """Get the most recently sent email."""
        return cls._sent_emails[-1] if cls._sent_emails else None

    @classmethod
    def get_emails_to(cls, email: str) -> List[MockEmail]:
        """Get all emails sent to a specific address."""
        return [e for e in cls._sent_emails if e.to_email == email]

    @classmethod
    def get_emails_with_subject(cls, subject: str) -> List[MockEmail]:
        """Get all emails with a specific subject."""
        return [e for e in cls._sent_emails if e.subject == subject]

    @classmethod
    def get_emails_containing(cls, text: str) -> List[MockEmail]:
        """Get all emails containing specific text in body."""
        return [
            e for e in cls._sent_emails
            if text in e.body_text or (e.body_html and text in e.body_html)
        ]

    @classmethod
    def clear_sent_emails(cls):
        """Clear all sent emails (for test isolation)."""
        cls._sent_emails.clear()

    @classmethod
    def set_fail_next(cls, fail: bool = True):
        """Set whether the next send should fail."""
        cls._fail_next = fail

    @classmethod
    def set_fail_for_email(cls, email: str):
        """Set a specific email address to always fail."""
        if email not in cls._fail_emails:
            cls._fail_emails.append(email)

    @classmethod
    def remove_fail_for_email(cls, email: str):
        """Remove a specific email from the fail list."""
        if email in cls._fail_emails:
            cls._fail_emails.remove(email)

    @classmethod
    def clear_fail_emails(cls):
        """Clear all failure settings."""
        cls._fail_emails.clear()
        cls._fail_next = False

    @classmethod
    def reset(cls):
        """Reset all mock state (emails and failure settings)."""
        cls._sent_emails.clear()
        cls._fail_emails.clear()
        cls._fail_next = False
        cls._simulate_delay = False

    @classmethod
    def email_count(cls) -> int:
        """Get the total number of sent emails."""
        return len(cls._sent_emails)

    @classmethod
    def assert_email_sent_to(cls, email: str) -> bool:
        """Assert that at least one email was sent to the address."""
        return any(e.to_email == email for e in cls._sent_emails)

    @classmethod
    def assert_email_sent_with_subject(cls, subject: str) -> bool:
        """Assert that at least one email was sent with the subject."""
        return any(e.subject == subject for e in cls._sent_emails)

    @classmethod
    def assert_no_emails_sent(cls) -> bool:
        """Assert that no emails were sent."""
        return len(cls._sent_emails) == 0
