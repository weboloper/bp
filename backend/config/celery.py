import os
from celery import Celery

# Django ayarlarını yükle
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('config')

# Django settings'den konfigürasyon al
app.config_from_object('django.conf:settings', namespace='CELERY')

# Tüm Django app'lerindeki task'ları otomatik keşfet
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
