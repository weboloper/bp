"""
Utility functions and helpers
Common utilities used across the application
"""
import re
import secrets
import string
import uuid
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from django.utils.text import slugify
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from PIL import Image
import hashlib


class TextUtils:
    """Text processing utilities"""
    
    @staticmethod
    def generate_slug(text: str, max_length: int = 50) -> str:
        """Generate URL-friendly slug from text"""
        slug = slugify(text)
        if len(slug) > max_length:
            slug = slug[:max_length].rsplit('-', 1)[0]
        return slug
    
    @staticmethod
    def truncate_words(text: str, word_count: int = 20) -> str:
        """Truncate text to specified word count"""
        words = text.split()
        if len(words) <= word_count:
            return text
        return ' '.join(words[:word_count]) + '...'
    
    @staticmethod
    def clean_phone_number(phone: str) -> str:
        """Clean and format phone number"""
        # Remove all non-digit characters
        cleaned = re.sub(r'[^\d]', '', phone)
        # Add country code if missing (assuming Turkey +90)
        if len(cleaned) == 10 and cleaned.startswith('5'):
            cleaned = '90' + cleaned
        elif len(cleaned) == 11 and cleaned.startswith('05'):
            cleaned = '90' + cleaned[1:]
        return cleaned
    
    @staticmethod
    def extract_mentions(text: str) -> list:
        """Extract @mentions from text"""
        pattern = r'@(\w+)'
        return re.findall(pattern, text)
    
    @staticmethod
    def extract_hashtags(text: str) -> list:
        """Extract #hashtags from text"""
        pattern = r'#(\w+)'
        return re.findall(pattern, text)


class ValidationUtils:
    """Validation utilities"""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email address"""
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def is_strong_password(password: str) -> Dict[str, Any]:
        """Check password strength"""
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        }
        
        score = sum(checks.values())
        strength = 'Weak'
        if score >= 4:
            strength = 'Strong'
        elif score >= 3:
            strength = 'Medium'
        
        return {
            'checks': checks,
            'score': score,
            'strength': strength,
            'is_strong': score >= 4
        }


class SecurityUtils:
    """Security related utilities"""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_verification_code(length: int = 6) -> str:
        """Generate numeric verification code"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    @staticmethod
    def hash_string(text: str, salt: str = '') -> str:
        """Generate SHA256 hash of string"""
        return hashlib.sha256((text + salt).encode()).hexdigest()
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate UUID4 string"""
        return str(uuid.uuid4())


class FileUtils:
    """File and image processing utilities"""
    
    @staticmethod
    def get_file_extension(filename: str) -> str:
        """Get file extension from filename"""
        return filename.split('.')[-1].lower() if '.' in filename else ''
    
    @staticmethod
    def is_image_file(filename: str) -> bool:
        """Check if file is an image"""
        image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']
        return FileUtils.get_file_extension(filename) in image_extensions
    
    @staticmethod
    def resize_image(image_path: str, max_width: int = 800, max_height: int = 600) -> bool:
        """Resize image while maintaining aspect ratio"""
        try:
            with Image.open(image_path) as img:
                img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                img.save(image_path, optimize=True, quality=85)
                return True
        except Exception:
            return False
    
    @staticmethod
    def generate_upload_path(instance, filename: str, folder: str = 'uploads') -> str:
        """Generate upload path for files"""
        ext = FileUtils.get_file_extension(filename)
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        date_path = timezone.now().strftime('%Y/%m/%d')
        return f"{folder}/{date_path}/{new_filename}"


class DateUtils:
    """Date and time utilities"""
    
    @staticmethod
    def time_ago(date) -> str:
        """Get human readable time ago string"""
        now = timezone.now()
        diff = now - date
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} yıl önce"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} ay önce"
        elif diff.days > 0:
            return f"{diff.days} gün önce"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} saat önce"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} dakika önce"
        else:
            return "Az önce"
    
    @staticmethod
    def is_business_hours(check_time=None) -> bool:
        """Check if given time is within business hours (9-18)"""
        if check_time is None:
            check_time = timezone.now()
        return 9 <= check_time.hour < 18 and check_time.weekday() < 5