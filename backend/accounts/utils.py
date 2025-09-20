import re
from PIL import Image
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.files.uploadedfile import InMemoryUploadedFile
from io import BytesIO
import sys
import os

def validate_alphanumeric_username(value):
    """Alphanumeric username validator (letters, numbers, underscore, dash)"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        raise ValidationError(_('Username can only contain letters, numbers, underscore and dash.'))

def validate_image_extension(value):
    """Validate image file extension (only JPEG, JPG, PNG allowed)"""
    allowed_extensions = ['.jpg', '.jpeg', '.png']
    ext = os.path.splitext(value.name)[1].lower()
    
    if ext not in allowed_extensions:
        raise ValidationError(_('Only JPEG, JPG and PNG images are allowed.'))

def resize_avatar(image, size=(300, 300)):
    """Resize avatar image to specified size"""
    if image:
        img = Image.open(image)
        
        # Convert to RGB if necessary
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        
        # Resize image
        img = img.resize(size, Image.Resampling.LANCZOS)
        
        # Save to BytesIO
        output = BytesIO()
        img.save(output, format='JPEG', quality=90)
        output.seek(0)
        
        # Create new InMemoryUploadedFile
        return InMemoryUploadedFile(
            output, 'ImageField', 
            f"{image.name.split('.')[0]}.jpg",
            'image/jpeg', sys.getsizeof(output), None
        )
    return image
