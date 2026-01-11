from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from .utils import validate_alphanumeric_username, validate_image_extension, resize_avatar

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        if not username:
            raise ValueError(_('The Username field must be set'))
        
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(username, email, password, **extra_fields)

class User(AbstractBaseUser,PermissionsMixin):
    # Authentication fields
    username = models.CharField(verbose_name=_('Username'), max_length=30, unique=True, validators=[validate_alphanumeric_username])
    email = models.EmailField(unique=True, verbose_name=_('Email'))

    # Status fields
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    is_staff = models.BooleanField(default=False, verbose_name=_('Staff'))
    is_verified = models.BooleanField(default=False, verbose_name=_('Email Verified'), help_text=_('Designates whether the user has verified their email address.'))
    
    # Dates
    date_joined = models.DateTimeField(auto_now_add=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    
    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
    
    def __str__(self):
        return self.username

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile', verbose_name=_('User'))
    first_name = models.CharField(max_length=30, blank=True, verbose_name=_('First Name'))
    last_name = models.CharField(max_length=30, blank=True, verbose_name=_('Last Name'))
    birth_date = models.DateField(null=True, blank=True, verbose_name=_('Birth Date'))
    bio = models.TextField(max_length=500, blank=True, verbose_name=_('Bio'))
    avatar = models.ImageField(upload_to='avatars/', validators=[validate_image_extension], null=True, blank=True, verbose_name=_('Avatar'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))

    class Meta:
        verbose_name = _('Profile')
        verbose_name_plural = _('Profiles')
    
    def __str__(self):
        return f"{self.user.username}'s Profile"
    
    def save(self, *args, **kwargs):
        # Resize avatar before saving
        if self.avatar:
            self.avatar = resize_avatar(self.avatar)
        super().save(*args, **kwargs)
