from django.db import models
from django.utils.translation import gettext_lazy as _


class PhoneCodeChoices(models.TextChoices):
    """Supported phone country codes"""
    TURKEY = '+90', _('Turkey (+90)')
    # USA = '+1', _('USA (+1)')


class ColorChoices(models.TextChoices):
    """Color choices for tags, categories, and UI elements"""
    LIGHT_BLUE = '#93C5FD', _('Light Blue')
    DARK_BLUE = '#3B82F6', _('Dark Blue')
    SKY_BLUE = '#7DD3FC', _('Sky Blue')
    INDIGO = '#818CF8', _('Indigo')
    LAVENDER = '#C4B5FD', _('Lavender')
    PURPLE = '#A78BFA', _('Purple')
    LILAC = '#C084FC', _('Lilac')
    PINK = '#F9A8D4', _('Pink')
    CORAL = '#FB923C', _('Coral')
    DEEP_ORANGE = '#F97316', _('Deep Orange')
    ORANGE = '#FDBA74', _('Orange')
    AMBER = '#FCD34D', _('Amber')
    YELLOW = '#FDE047', _('Yellow')
    LIME = '#BEF264', _('Lime')
    GREEN = '#86EFAC', _('Green')
    TEAL = '#5EEAD4', _('Teal')
    CYAN = '#67E8F9', _('Cyan')


class CurrencyChoices(models.TextChoices):
    """Supported currencies"""
    TRY = 'TRY', _('Turkish Lira (TRY)')
    # USD = 'USD', _('US Dollar (USD)')
    # EUR = 'EUR', _('Euro (EUR)')
