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
    """
    Avatar için akıllı resize - Her zaman merkezi kare crop
    
    Nasıl çalışır:
    1. Resmi aç ve RGB'ye çevir
    2. Merkezi kare crop (uzun kenardan kırp)
    3. Hedef boyuta resize (300x300)
    4. JPEG olarak kaydet
    
    Sonuç: Her zaman mükemmel kare avatar
    """
    if not image:
        return image
    
    try:
        # Resmi aç
        img = Image.open(image)
        
        # RGB'ye çevir
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        
        # Mevcut boyutlar
        width, height = img.size
        
        # Kare crop için merkezi hesapla
        if width > height:
            # Yatay resim - ortadan kare kes
            left = (width - height) // 2
            top = 0
            right = left + height
            bottom = height
        else:
            # Dikey resim - ortadan kare kes
            left = 0
            top = (height - width) // 2
            right = width
            bottom = top + width
        
        # Merkezi kare crop
        img = img.crop((left, top, right, bottom))
        
        # Hedefe resize (artık kare olduğu için bozulma olmaz)
        img = img.resize(size, Image.Resampling.LANCZOS)
        
        # BytesIO'ya kaydet
        output = BytesIO()
        img.save(output, format='JPEG', quality=90, optimize=True)
        output.seek(0)
        
        # Yeni dosya adı
        original_name = os.path.splitext(image.name)[0]
        
        return InMemoryUploadedFile(
            output,
            'ImageField',
            f"{original_name}.jpg",
            'image/jpeg',
            output.getbuffer().nbytes,
            None
        )
    except Exception as e:
        print(f"Error resizing avatar: {e}")
        import traceback
        traceback.print_exc()
        return image
