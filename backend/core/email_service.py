"""
Email Service Module
Centralized email handling for the entire application
"""
import logging
from typing import List, Dict, Any, Optional
from django.conf import settings
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from celery import shared_task

logger = logging.getLogger(__name__)


class EmailService:
    """
    Centralized email service for consistent email handling across the application
    """
    
    @staticmethod
    def send_simple_email(
        subject: str,
        message: str,
        recipient_list: List[str],
        from_email: str = None
    ) -> bool:
        """Send a simple text email"""
        try:
            from_email = from_email or settings.DEFAULT_FROM_EMAIL
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
            )
            logger.info(f"Simple email sent to {len(recipient_list)} recipients")
            return True
        except Exception as e:
            logger.error(f"Failed to send simple email: {str(e)}")
            return False
    
    @staticmethod
    def send_template_email(
        template_name: str,
        context: Dict[str, Any],
        subject: str,
        recipient_list: List[str],
        from_email: str = None
    ) -> bool:
        """Send an email using HTML template"""
        try:
            from_email = from_email or settings.DEFAULT_FROM_EMAIL
            
            # Render HTML content
            html_content = render_to_string(f'emails/{template_name}.html', context)
            text_content = strip_tags(html_content)
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=from_email,
                to=recipient_list
            )
            email.attach_alternative(html_content, "text/html")
            email.send()
            
            logger.info(f"Template email sent to {len(recipient_list)} recipients")
            return True
        except Exception as e:
            logger.error(f"Failed to send template email: {str(e)}")
            return False
    
    @staticmethod
    def send_bulk_email(
        subject: str,
        message: str,
        recipient_list: List[str],
        template_name: str = None,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Send bulk emails with success/failure tracking"""
        successful = []
        failed = []
        
        for recipient in recipient_list:
            try:
                if template_name and context:
                    success = EmailService.send_template_email(
                        template_name=template_name,
                        context=context,
                        subject=subject,
                        recipient_list=[recipient]
                    )
                else:
                    success = EmailService.send_simple_email(
                        subject=subject,
                        message=message,
                        recipient_list=[recipient]
                    )
                
                if success:
                    successful.append(recipient)
                else:
                    failed.append(recipient)
            except Exception as e:
                logger.error(f"Bulk email failed for {recipient}: {str(e)}")
                failed.append(recipient)
        
        return {
            'successful': successful,
            'failed': failed,
            'success_count': len(successful),
            'failure_count': len(failed)
        }


# Async email tasks for Celery
@shared_task
def send_async_email(subject: str, message: str, recipient_list: List[str]):
    """Async email sending task"""
    return EmailService.send_simple_email(subject, message, recipient_list)


@shared_task
def send_async_template_email(
    template_name: str,
    context: Dict[str, Any],
    subject: str,
    recipient_list: List[str]
):
    """Async template email sending task"""
    return EmailService.send_template_email(
        template_name, context, subject, recipient_list
    )