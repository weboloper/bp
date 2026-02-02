"""
Celery tasks for async notification sending.
"""
from celery import shared_task
from providers.registry import get_email_backend, get_sms_backend


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_email_task(self, to, subject, body, **kwargs):
    """
    Async email sending task.

    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body (HTML or plain text)
        **kwargs: Additional backend-specific options
    """
    try:
        backend = get_email_backend()
        return backend.send(to=to, subject=subject, body=body, **kwargs)
    except Exception as e:
        self.retry(exc=e)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_template_email_task(self, recipient_list, subject, template_name, context, from_email):
    """
    Async template email sending task.

    Args:
        recipient_list: List of recipient email addresses
        subject: Email subject
        template_name: Template path
        context: Template context
        from_email: From email address
    """
    try:
        from notifications.services.dispatcher import _send_template_email_sync
        return _send_template_email_sync(
            recipient_list=recipient_list,
            subject=subject,
            template_name=template_name,
            context=context,
            from_email=from_email
        )
    except Exception as e:
        self.retry(exc=e)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_sms_task(self, to, message, **kwargs):
    """
    Async SMS sending task.

    Args:
        to: Recipient phone number
        message: SMS message content
        **kwargs: Additional backend-specific options
    """
    try:
        backend = get_sms_backend()
        return backend.send(to=to, message=message, **kwargs)
    except Exception as e:
        self.retry(exc=e)
