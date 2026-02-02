"""
Custom validators for models and forms
"""
import re
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _


def validate_turkish_phone(value):
    """Validate Turkish phone number format"""
    # Remove all non-digit characters
    cleaned = re.sub(r'[^\d]', '', str(value))
    
    # Check various Turkish phone formats
    valid_patterns = [
        r'^90[0-9]{10}$',  # +90XXXXXXXXXX
        r'^0[0-9]{10}$',   # 0XXXXXXXXXX
        r'^[0-9]{10}$',    # XXXXXXXXXX (mobile without 0)
    ]
    
    is_valid = any(re.match(pattern, cleaned) for pattern in valid_patterns)
    
    if not is_valid:
        raise ValidationError(_('Geçerli bir telefon numarası giriniz.'))


def validate_turkish_tc(value):
    """Validate Turkish TC Identity Number"""
    tc = str(value)
    
    # TC must be 11 digits
    if len(tc) != 11 or not tc.isdigit():
        raise ValidationError(_('TC Kimlik No 11 haneli olmalıdır.'))
    
    # First digit cannot be 0
    if tc[0] == '0':
        raise ValidationError(_('TC Kimlik No 0 ile başlayamaz.'))
    
    # Algorithm check
    digits = [int(d) for d in tc]
    
    # 10th digit check
    sum_odd = sum(digits[i] for i in range(0, 9, 2))  # 1st, 3rd, 5th, 7th, 9th
    sum_even = sum(digits[i] for i in range(1, 8, 2))  # 2nd, 4th, 6th, 8th
    
    if ((sum_odd * 7) - sum_even) % 10 != digits[9]:
        raise ValidationError(_('Geçersiz TC Kimlik No.'))
    
    # 11th digit check
    if (sum(digits[:10]) % 10) != digits[10]:
        raise ValidationError(_('Geçersiz TC Kimlik No.'))


def validate_strong_password(value):
    """Validate password strength"""
    if len(value) < 8:
        raise ValidationError(_('Şifre en az 8 karakter olmalıdır.'))
    
    if not re.search(r'[A-Z]', value):
        raise ValidationError(_('Şifre en az bir büyük harf içermelidir.'))
    
    if not re.search(r'[a-z]', value):
        raise ValidationError(_('Şifre en az bir küçük harf içermelidir.'))
    
    if not re.search(r'\d', value):
        raise ValidationError(_('Şifre en az bir rakam içermelidir.'))


def validate_slug_unique(model_class, exclude_pk=None):
    """Validate that slug is unique for given model"""
    def validator(value):
        query = model_class.objects.filter(slug=value)
        if exclude_pk:
            query = query.exclude(pk=exclude_pk)
        
        if query.exists():
            raise ValidationError(_('Bu slug zaten kullanımda.'))
    
    return validator


def validate_image_size(max_size_mb=5):
    """Validate uploaded image size"""
    def validator(value):
        if value.size > max_size_mb * 1024 * 1024:
            raise ValidationError(
                _('Dosya boyutu %(max_size)s MB\'dan büyük olamaz.') % 
                {'max_size': max_size_mb}
            )
    return validator


def validate_file_extension(allowed_extensions):
    """Validate file extension"""
    def validator(value):
        ext = value.name.split('.')[-1].lower() if '.' in value.name else ''
        if ext not in allowed_extensions:
            raise ValidationError(
                _('Geçersiz dosya formatı. İzin verilen formatlar: %(extensions)s') %
                {'extensions': ', '.join(allowed_extensions)}
            )
    return validator


def validate_positive_number(value):
    """Validate that number is positive"""
    if value <= 0:
        raise ValidationError(_('Bu alan pozitif bir sayı olmalıdır.'))


def validate_iban(value):
    """Validate Turkish IBAN format"""
    # Remove spaces and convert to uppercase
    iban = str(value).replace(' ', '').upper()
    
    # Turkish IBAN format: TR + 2 check digits + 5 bank code + 1 reserve + 16 account number = 26 chars
    if len(iban) != 26 or not iban.startswith('TR'):
        raise ValidationError(_('Geçerli bir IBAN giriniz.'))
    
    # Check if all characters after TR are digits
    if not iban[2:].isdigit():
        raise ValidationError(_('IBAN sadece rakam içermelidir.'))


# Predefined validators
turkish_phone_validator = RegexValidator(
    regex=r'^(\+90|0)?[0-9]{10}$',
    message=_('Geçerli bir telefon numarası giriniz.')
)

alphanumeric_validator = RegexValidator(
    regex=r'^[a-zA-Z0-9]*$',
    message=_('Sadece harf ve rakam kullanabilirsiniz.')
)

slug_validator = RegexValidator(
    regex=r'^[-a-zA-Z0-9_]+$',
    message=_('Slug sadece harf, rakam, tire ve alt çizgi içerebilir.')
)