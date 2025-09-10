from django.conf import settings

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
    
    Public Methods:
    - send_smart_email(): For normal emails (welcome, newsletter, notifications)
    - send_critical_email(): For critical emails (verification, password reset)
    """
    
    @staticmethod
    def send_smart_email(
        template_name: str,
        context: Dict[str, Any],
        subject: str,
        recipient_list: List[str],
        from_email: str = None,
        force_sync: bool = False
    ) -> bool:
        """
        Smart email sending - automatically choose sync or async based on settings
        Use this for: welcome emails, newsletters, notifications
        
        Args:
            template_name: Email template name (without .html)
            context: Template context data
            subject: Email subject
            recipient_list: List of recipient emails
            from_email: From email address (optional)
            force_sync: Force synchronous sending
        """
        # Critical emails or forced sync always send synchronously
        if force_sync or not getattr(settings, 'USE_ASYNC_EMAIL', False):
            return EmailService._send_template_email(
                template_name=template_name,
                context=context,
                subject=subject,
                recipient_list=recipient_list,
                from_email=from_email
            )
        else:
            # Send asynchronously if Celery is available
            try:
                send_async_template_email.delay(
                    template_name=template_name,
                    context=context,
                    subject=subject,
                    recipient_list=recipient_list
                )
                return True
            except Exception as e:
                logger.warning(f"Async email failed, falling back to sync: {str(e)}")
                # Fallback to synchronous sending
                return EmailService._send_template_email(
                    template_name=template_name,
                    context=context,
                    subject=subject,
                    recipient_list=recipient_list,
                    from_email=from_email
                )
    
    @staticmethod
    def send_critical_email(
        template_name: str,
        context: Dict[str, Any],
        subject: str,
        recipient_list: List[str],
        from_email: str = None
    ) -> bool:
        """
        Send critical emails - always synchronous
        Use this for: email verification, password reset, important notifications
        
        Args:
            template_name: Email template name (without .html)
            context: Template context data
            subject: Email subject
            recipient_list: List of recipient emails
            from_email: From email address (optional)
        """
        return EmailService._send_template_email(
            template_name=template_name,
            context=context,
            subject=subject,
            recipient_list=recipient_list,
            from_email=from_email
        )
    
    # Private methods - Internal use only
    
    @staticmethod
    def _send_simple_email(
        subject: str,
        message: str,
        recipient_list: List[str],
        from_email: str = None
    ) -> bool:
        """Send a simple text email - Internal use only"""
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
    def _send_template_email(
        template_name: str,
        context: Dict[str, Any],
        subject: str,
        recipient_list: List[str],
        from_email: str = None
    ) -> bool:
        """Send an email using HTML template - Internal use only"""
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
    def _send_bulk_email(
        subject: str,
        message: str,
        recipient_list: List[str],
        template_name: str = None,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Send bulk emails with success/failure tracking - Internal use only"""
        successful = []
        failed = []
        
        for recipient in recipient_list:
            try:
                if template_name and context:
                    success = EmailService._send_template_email(
                        template_name=template_name,
                        context=context,
                        subject=subject,
                        recipient_list=[recipient]
                    )
                else:
                    success = EmailService._send_simple_email(
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
def send_async_template_email(
    template_name: str,
    context: Dict[str, Any],
    subject: str,
    recipient_list: List[str]
):
    """Async template email sending task - Internal use only"""
    return EmailService._send_template_email(
        template_name, context, subject, recipient_list
    )