# Bu dosya Celery app'in Django ile beraber yüklenmesini sağlar
from .celery import app as celery_app

__all__ = ('celery_app',)
