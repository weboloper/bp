"""
NetGSM SMS Provider - Turkey's popular SMS gateway

API Documentation: https://www.netgsm.com.tr/dokuman/
"""
import logging
import requests
from typing import List, Dict, Any, Optional

from .base import BaseSMSProvider, SMSResult, BulkSMSResult, SMSStatus

logger = logging.getLogger(__name__)


class NetGSMProvider(BaseSMSProvider):
    """
    NetGSM SMS Provider implementation.

    Handles:
    - Single SMS sending
    - Bulk SMS sending (XML API)
    - Delivery reports
    - Balance checking
    """

    # API Endpoints
    BASE_URL = "https://api.netgsm.com.tr"
    SEND_SMS_URL = f"{BASE_URL}/sms/send/get"
    SEND_BULK_URL = f"{BASE_URL}/sms/send/xml"
    REPORT_URL = f"{BASE_URL}/sms/report"
    BALANCE_URL = f"{BASE_URL}/balance/list/get"

    # NetGSM Error Codes
    ERROR_CODES = {
        '00': 'Başarısız gönderim',
        '01': 'Geçersiz kullanıcı adı veya şifre',
        '02': 'Bakiye yetersiz',
        '03': 'Geçersiz başlık (msgheader)',
        '04': 'Mesaj başlığı tanımlı değil',
        '05': 'Mesaj başlığı kullanım izni yok',
        '06': 'Geçersiz mesaj',
        '07': 'Gönderilecek numara yok',
        '08': 'Gönderim tarih formatı hatalı',
        '09': 'Birden fazla gönderim yapılıyor',
        '10': 'Mesaj boyu aşıldı',
        '11': 'Sistem hatası',
        '20': 'Tanımsız hata',
        '30': 'Geçersiz paket ID',
        '40': 'Aynı içerikli SMS var',
        '50': 'Başlık tanımlı değil',
        '51': 'Başlık izni yok',
        '52': 'Başlık aktif değil',
        '60': 'Hesabınız aktif değil',
        '70': 'Hatalı sorgulama',
        '80': 'Gönderim sınırı aşıldı',
        '100': 'Sistem hatası',
    }

    # Delivery Status Codes
    DELIVERY_CODES = {
        '0': SMSStatus.PENDING,
        '1': SMSStatus.DELIVERED,
        '2': SMSStatus.FAILED,
        '3': SMSStatus.REJECTED,
        '4': SMSStatus.REJECTED,
        '5': SMSStatus.REJECTED,
        '6': SMSStatus.REJECTED,
        '11': SMSStatus.PENDING,
        '12': SMSStatus.SENT,
    }

    @property
    def provider_name(self) -> str:
        return 'netgsm'

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        sender_id: Optional[str] = None
    ):
        """
        Initialize NetGSM provider.

        Args:
            username: NetGSM API username
            password: NetGSM API password
            sender_id: Default sender ID
        """
        self.username = username or ''
        self.password = password or ''
        self.default_sender_id = sender_id or 'SALON'
        self.timeout = 30

    def send(
        self,
        phone: str,
        message: str,
        sender_id: Optional[str] = None
    ) -> SMSResult:
        """
        Send a single SMS via NetGSM.
        """
        if not self.validate_phone(phone):
            return SMSResult(
                success=False,
                status=SMSStatus.FAILED,
                error_code='INVALID_PHONE',
                error_message='Geçersiz telefon numarası'
            )

        formatted_phone = f"90{self.normalize_phone(phone)}"
        credits = self.calculate_credits(message)

        params = {
            'usercode': self.username,
            'password': self.password,
            'gsmno': formatted_phone,
            'message': message,
            'msgheader': sender_id or self.default_sender_id,
            'dil': 'TR',
        }

        try:
            response = requests.get(
                self.SEND_SMS_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            result_code = response.text.strip()

            if result_code.isdigit() and len(result_code) > 5:
                logger.info(f"SMS sent successfully to {phone}, ID: {result_code}")
                return SMSResult(
                    success=True,
                    message_id=result_code,
                    status=SMSStatus.SENT,
                    credits_used=credits,
                    raw_response={'code': result_code}
                )
            else:
                error_msg = self.ERROR_CODES.get(result_code, f'Bilinmeyen hata: {result_code}')
                logger.error(f"SMS send failed to {phone}: {error_msg}")
                return SMSResult(
                    success=False,
                    status=SMSStatus.FAILED,
                    error_code=result_code,
                    error_message=error_msg,
                    raw_response={'code': result_code}
                )

        except requests.RequestException as e:
            logger.exception(f"NetGSM API error: {e}")
            return SMSResult(
                success=False,
                status=SMSStatus.FAILED,
                error_code='API_ERROR',
                error_message=str(e)
            )

    def send_bulk(
        self,
        recipients: List[str],
        message: str,
        sender_id: Optional[str] = None
    ) -> BulkSMSResult:
        """
        Send SMS to multiple recipients via NetGSM XML API.
        """
        if not recipients:
            return BulkSMSResult(
                success=False,
                error_message='Alıcı listesi boş'
            )

        valid_phones = []
        for phone in recipients:
            if self.validate_phone(phone):
                valid_phones.append(f"90{self.normalize_phone(phone)}")

        if not valid_phones:
            return BulkSMSResult(
                success=False,
                error_message='Geçerli telefon numarası bulunamadı'
            )

        credits_per_msg = self.calculate_credits(message)
        xml_content = self._build_bulk_xml(
            valid_phones,
            message,
            sender_id or self.default_sender_id
        )

        try:
            response = requests.post(
                self.SEND_BULK_URL,
                data=xml_content.encode('utf-8'),
                headers={'Content-Type': 'application/xml; charset=utf-8'},
                timeout=self.timeout
            )
            response.raise_for_status()

            result_code = response.text.strip()

            if result_code.isdigit() and len(result_code) > 5:
                successful = len(valid_phones)
                logger.info(f"Bulk SMS sent, Batch ID: {result_code}, Count: {successful}")
                return BulkSMSResult(
                    success=True,
                    batch_id=result_code,
                    total=len(recipients),
                    successful=successful,
                    failed=len(recipients) - successful,
                    credits_used=successful * credits_per_msg
                )
            else:
                error_msg = self.ERROR_CODES.get(result_code, f'Bilinmeyen hata: {result_code}')
                logger.error(f"Bulk SMS failed: {error_msg}")
                return BulkSMSResult(
                    success=False,
                    total=len(recipients),
                    failed=len(recipients),
                    error_message=error_msg
                )

        except requests.RequestException as e:
            logger.exception(f"NetGSM Bulk API error: {e}")
            return BulkSMSResult(
                success=False,
                total=len(recipients),
                failed=len(recipients),
                error_message=str(e)
            )

    def _build_bulk_xml(
        self,
        phones: List[str],
        message: str,
        sender_id: str
    ) -> str:
        """Build XML payload for bulk SMS."""
        phones_xml = '\n'.join([f'<no>{phone}</no>' for phone in phones])

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<mainbody>
    <header>
        <company dession="1">Netgsm</company>
        <usercode>{self.username}</usercode>
        <password>{self.password}</password>
        <type>1:n</type>
        <msgheader>{sender_id}</msgheader>
    </header>
    <body>
        <msg><![CDATA[{message}]]></msg>
        {phones_xml}
    </body>
</mainbody>"""

    def get_delivery_report(self, message_id: str) -> SMSResult:
        """
        Get delivery status for a sent message.
        """
        params = {
            'usercode': self.username,
            'password': self.password,
            'bulkid': message_id,
            'type': '0',
        }

        try:
            response = requests.get(
                self.REPORT_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            result = response.text.strip()

            if result.startswith('00') or result.startswith('01'):
                parts = result.split(' ')
                if len(parts) >= 2:
                    status_code = parts[1] if len(parts) > 1 else '0'
                    status = self.DELIVERY_CODES.get(status_code, SMSStatus.PENDING)

                    return SMSResult(
                        success=True,
                        message_id=message_id,
                        status=status,
                        raw_response={'result': result}
                    )

            error_msg = self.ERROR_CODES.get(result[:2], f'Bilinmeyen hata: {result}')
            return SMSResult(
                success=False,
                message_id=message_id,
                status=SMSStatus.PENDING,
                error_code=result[:2],
                error_message=error_msg
            )

        except requests.RequestException as e:
            logger.exception(f"NetGSM Report API error: {e}")
            return SMSResult(
                success=False,
                message_id=message_id,
                status=SMSStatus.PENDING,
                error_code='API_ERROR',
                error_message=str(e)
            )

    def get_balance(self) -> Dict[str, Any]:
        """
        Get account balance from NetGSM.
        """
        params = {
            'usercode': self.username,
            'password': self.password,
            'tip': '1',
        }

        try:
            response = requests.get(
                self.BALANCE_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            result = response.text.strip()
            parts = result.split()

            if len(parts) >= 1 and parts[0].replace('.', '').replace(',', '').isdigit():
                balance = float(parts[0].replace(',', '.'))
                currency = parts[1] if len(parts) > 1 else 'TL'

                return {
                    'success': True,
                    'provider': 'netgsm',
                    'balance': balance,
                    'currency': currency,
                    'raw_response': result
                }
            else:
                error_msg = self.ERROR_CODES.get(result[:2], f'Bakiye sorgulanamadı: {result}')
                return {
                    'success': False,
                    'provider': 'netgsm',
                    'error': error_msg,
                    'raw_response': result
                }

        except requests.RequestException as e:
            logger.exception(f"NetGSM Balance API error: {e}")
            return {
                'success': False,
                'provider': 'netgsm',
                'error': str(e)
            }
