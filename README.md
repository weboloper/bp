# BP - Django Docker Boilerplate

Modern Django backend projesi için Docker tabanlı boilerplate. Celery, Redis, PostgreSQL ve Nginx ile production-ready yapı. **Development, Staging ve Production** ortamlarını destekler.

## 🚀 Kurulum Rehberleri

Hangi ortamda çalışacağınıza göre adım adım rehber seçin:

### 📋 Kurulum Seçenekleri

| Ortam | Ne Zaman Kullan | SSL | Database |
|-------|----------------|-----|----------|
| **[🔧 cPanel](#-cpanel-kurulumu)** | Shared hosting | Manuel | Shared |
| **[💻 Development](#-development-kurulumu)** | Yerel geliştirme | HTTP | Container |
| **[🧪 Staging](#-staging-kurulumu)** | Test & Demo | Test SSL | Container |  
| **[🚀 Production](#-production-kurulumu)** | Canlı sistem | Real SSL | Managed |

---

## 🔧 cPanel Kurulumu

**cPanel shared hosting için adım adım kurulum**

### 1. Dosya Yükleme
```bash
# Projeyi zip olarak indir
# cPanel File Manager ile public_html'e yükle
# veya Git ile:
cd public_html
git clone https://github.com/weboloper/bp.git .
```

### 2. Python App Kurulumu
```bash
# cPanel > Python App > Create Application:
# - Python Version: 3.11
# - Application Root: public_html
# - Application URL: yourdomain.com
# - Application Startup File: passenger_wsgi.py
```

### 3. Environment Variables
```bash
# cPanel > Python App > Environment Variables:
SECRET_KEY=your-secret-key
DEBUG=False
DATABASE_URL=mysql://user:pass@localhost/dbname
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

### 4. Dependencies Kurulumu
```bash
# cPanel Terminal:
cd public_html
source /home/username/virtualenv/public_html/3.11/bin/activate
pip install -r backend/requirements.txt
```

### 5. Django Setup
```bash
# Database migration:
python backend/manage.py migrate

# Static files:
python backend/manage.py collectstatic --noinput

# Superuser:
python backend/manage.py createsuperuser
```

### 6. SSL Setup (cPanel)
```bash
# cPanel > SSL/TLS > Let's Encrypt
# Domain seç ve SSL aktifleştir

# .htaccess ile HTTPS yönlendir:
cp htaccess.cpanel.example .htaccess
```

**✅ cPanel kurulumu tamamlandı!**
- URL: https://yourdomain.com
- Admin: https://yourdomain.com/admin

---

## 💻 Development Kurulumu

**Yerel geliştirme ortamı kurulumu**

### 1. Projeyi Klonla
```bash
git clone https://github.com/weboloper/bp.git
cd bp
```

### 2. Environment Hazırlığı
```bash
# Development environment dosyasını oluştur
cp .env.example .env

# .env dosyasını düzenle:
nano .env
# - SECRET_KEY değiştir
# - PostgreSQL şifrelerini güncelle
```

### 3. Development Başlat
```bash
# Docker imajlarını oluştur
make build

# Development servisleri başlat
make up

# Database migration
make migrate

# Admin kullanıcısı oluştur
make createsuperuser
```

### 4. Test Et
```bash
# Servislerin çalıştığını kontrol et
curl http://localhost/api/

# Admin panel: http://localhost/admin/
# API: http://localhost/api/
```

### 🔧 Development Komutları
```bash
make help              # Tüm komutları göster
make up                # Servisleri başlat  
make down              # Servisleri durdur
make logs              # Logları göster
make shell             # Backend container'a bağlan
make migrate           # Migration çalıştır
make test              # Testleri çalıştır
make restart           # Servisleri yeniden başlat
```

**✅ Development hazır!**
- API: http://localhost/api/
- Admin: http://localhost/admin/
- Backend: http://localhost:8000

---

## 🧪 Staging Kurulumu

**Test ve client demo ortamı kurulumu**

### 1. VPS Hazırlığı
```bash
# VPS'e bağlan ve gerekli paketleri kur
sudo apt update && sudo apt install docker.io docker-compose git

# Projeyi klonla
git clone https://github.com/weboloper/bp.git
cd bp
```

### 2. Staging Environment
```bash
# Staging environment dosyasını oluştur
cp .env.staging.example .env.staging

# .env.staging dosyasını düzenle:
nano .env.staging
# - DOMAIN=staging.yourdomain.com
# - SSL_EMAIL=your-email@domain.com
# - SECRET_KEY değiştir
# - ALLOWED_HOSTS=staging.yourdomain.com
```

### Staging Deploy
```bash
# Staging için Docker imajlarını oluştur
make build-staging

# Staging servisleri başlat (SSL container otomatik dahil)
make up-staging

# Database migration
make migrate-staging

# Static dosyaları topla
make collectstatic-staging

# Admin kullanıcısı oluştur
make createsuperuser-staging
```

### 4. SSL Setup (Otomatik)
```bash
# SSL container otomatik test sertifikası alır
# DNS'i sunucuya yönlendirin: staging.yourdomain.com -> SERVER_IP

# SSL loglarını kontrol et:
make logs-staging-ssl

# Test et (test sertifikası için -k flag gerekli):
curl -k -I https://staging.yourdomain.com
```

### 🧪 Staging Komutları
```bash
make build-staging     # Staging imajlarını oluştur
make up-staging        # Staging servisleri başlat
make down-staging      # Staging servisleri durdur
make logs-staging      # Staging logları
make logs-staging-ssl  # Staging SSL logları
make restart-staging   # Staging servisleri yeniden başlat
```

**✅ Staging hazır!**
- URL: https://staging.yourdomain.com (test SSL)
- Admin: https://staging.yourdomain.com/admin/
- API: https://staging.yourdomain.com/api/

---

## 🚀 Production Kurulumu  

**Canlı sistem kurulumu**

### 1. VPS Hazırlığı
```bash
# Production VPS'e bağlan
sudo apt update && sudo apt install docker.io docker-compose git

# Projeyi klonla
git clone https://github.com/weboloper/bp.git
cd bp
```

### 2. Managed Database Kurulumu
```bash
# DigitalOcean/AWS/Azure'da managed PostgreSQL oluştur
# Connection string'i al:
# postgresql://username:password@host:5432/dbname
```

### 3. Production Environment
```bash
# Production environment dosyasını oluştur
cp .env.prod.example .env.prod

# .env.prod dosyasını düzenle:
nano .env.prod
# - DEBUG=False
# - SECRET_KEY=super-guclu-secret-key
# - DATABASE_URL=postgresql://user:pass@managed-db-host:5432/dbname
# - DOMAIN=yourdomain.com
# - SSL_EMAIL=your-email@domain.com
# - ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

### 4. Production Deploy
```bash
# Production için Docker imajlarını oluştur
make build-prod

# Production servisleri başlat (SSL container otomatik dahil)
make up-prod

# Database migration
make migrate-prod

# Superuser oluştur
make createsuperuser-prod

# Static dosyaları topla
make collectstatic-prod
```

### 5. SSL Setup (Otomatik)
```bash
# DNS'i sunucuya yönlendir: yourdomain.com -> SERVER_IP
# SSL container otomatik gerçek sertifika alacak

# SSL durumunu kontrol et:
make logs-ssl
make ssl-container-status

# HTTPS yönlendirmesini aktifleştir:
make ssl-enable-https
make restart-prod

# Test et:
curl -I https://yourdomain.com
```

### 🚀 Production Komutları
```bash
make build-prod        # Production imajlarını oluştur
make up-prod           # Production servisleri başlat
make down-prod         # Production servisleri durdur
make logs-prod         # Production logları
make logs-ssl          # SSL container logları
make restart-prod      # Production servisleri yeniden başlat
make migrate-prod      # Production migration
make ssl-container-status  # SSL durumu
```

### 🔒 SSL Yönetimi (Otomatik)
```bash
# SSL container durumu
make ssl-container-status              # Container durumu
make logs-ssl                          # SSL logları

# Manuel SSL işlemleri
make ssl-container-manual-renew        # Manuel yenileme
make ssl-container-restart             # Container yeniden başlat

# SSL container 12 saatte bir otomatik yeniler!
```

**✅ Production hazır!**
- URL: https://yourdomain.com
- Admin: https://yourdomain.com/admin/
- API: https://yourdomain.com/api/

---

## 🔒 SSL Detaylı Kurulum

SSL artık **ana compose dosyalarına entegre** - ayrı SSL dosyaları gereksiz!

### SSL Nasıl Çalışır?
- **Production**: `docker-compose.prod.yml` → `certbot` servisi (gerçek SSL)
- **Staging**: `docker-compose.staging.yml` → `certbot-staging` servisi (test SSL)

### SSL Container (Varsayılan - Otomatik)
```bash
# Production SSL (otomatik dahil)
make up-prod                           # SSL container otomatik başlar
make logs-ssl                          # SSL loglarını görüntüle
make ssl-container-status              # SSL durumunu kontrol et

# Staging SSL (otomatik dahil)
make up-staging                        # SSL container otomatik başlar
make logs-staging-ssl                  # Staging SSL logları

# Manuel SSL işlemleri
make ssl-container-manual-renew        # Production manuel yenileme
make ssl-container-restart             # Production container restart
```

### SSL Cron Job (Alternatif)
```bash
# Traditional cron job yaklaşımı
make ssl-init                          # İlk sertifika al
make ssl-setup-cron                    # Otomatik yenileme kur
make ssl-renew                         # Manuel yenileme
make ssl-status                        # Sertifika durumu
```

### HTTPS Yönlendirme (Ortak)
```bash
make ssl-enable-https                  # HTTPS yönlendirmesini aç
make ssl-disable-https                 # HTTPS yönlendirmesini kapat
```

**📚 Detaylı SSL kurulumu için [SSL-SETUP.md](./SSL-SETUP.md) dosyasını inceleyin.**

---

## 🛠 Sık Kullanılan Komutlar

### Development (Günlük Kullanım)
```bash
make up                # Servisleri başlat
make down              # Servisleri durdur  
make logs              # Logları göster
make shell             # Backend container'a gir
make migrate           # Migration çalıştır
make test              # Testleri çalıştır
make restart           # Servisleri yeniden başlat
```

### Production (Deployment & Monitoring)
```bash
make build-prod        # Production imajlarını oluştur
make up-prod           # Production servisleri başlat
make down-prod         # Production servisleri durdur
make logs-prod         # Production logları
make migrate-prod      # Production migration
make restart-prod      # Production servisleri yeniden başlat
```

### SSL Yönetimi (Production/Staging)
```bash
make logs-ssl          # Production SSL logları
make logs-staging-ssl  # Staging SSL logları
make ssl-container-status         # SSL container durumu
make ssl-container-restart        # Production SSL restart
make ssl-container-manual-renew   # Production manuel SSL yenileme
```

### Database İşlemleri
```bash
make migrate           # Development migration
make migrate-prod      # Production migration
make migrate-staging   # Staging migration
make makemigrations    # Yeni migration oluştur
make shell-db          # PostgreSQL shell (development)

# Static files
make collectstatic     # Development static files
make collectstatic-prod    # Production static files
make collectstatic-staging # Staging static files
```

### Debugging & Monitoring
```bash
make logs              # Development tüm loglar
make logs-prod         # Production tüm loglar
make logs-backend      # Sadece backend logları
make logs-celery       # Celery logları
make shell             # Backend container shell
```

---

## 🏗️ Proje Yapısı

```
bp/
├── backend/                       # Django uygulaması
│   ├── config/                   # Django settings
│   ├── apps/                     # Django apps
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile                # Backend Docker image
├── nginx/                        # Nginx reverse proxy
│   ├── default.conf              # Nginx konfigürasyonu
│   ├── ssl/                      # SSL sertifikaları
│   └── Dockerfile                # Nginx Docker image
├── scripts/                      # Utility scripts
├── docker-compose.yml            # Development servisleri
├── docker-compose.staging.yml    # Staging servisleri (SSL entegre)
├── docker-compose.prod.yml       # Production servisleri (SSL entegre)
├── .env.example                  # Development environment örneği
├── .env.staging.example          # Staging environment örneği
├── .env.prod.example             # Production environment örneği
├── Makefile                      # Kolay komutlar
├── SSL-SETUP.md                  # SSL kurulum rehberi
└── README.md                     # Bu dosya
```

## 🌐 Ortamlar ve Port'lar

| Ortam | Backend | Nginx | Database | Redis | SSL | URL |
|-------|---------|-------|----------|-------|-----|-----|
| **Development** | 8000 | 80 | 5432 | 6379 | - | http://localhost |
| **Staging** | 8001 | 8080, 8443 | 5433 | 6380 | Test | https://staging.domain.com |
| **Production** | 8000 | 80, 443 | External | 6379 | Real | https://domain.com |

## 📦 Servisler

### Development Servisleri
- **Backend**: Django + DRF
- **Database**: PostgreSQL (Container)
- **Cache**: Redis (Container)
- **Queue**: Celery + Celery Beat
- **Proxy**: Nginx

### Production Servisleri
- **Backend**: Django + DRF (Gunicorn)
- **Database**: External Managed PostgreSQL
- **Cache**: Redis (Container)
- **Queue**: Celery + Celery Beat
- **Proxy**: Nginx + SSL
- **SSL**: Certbot Container (Otomatik yenileme)

## 🔧 Özelleştirme

### Environment Variables

**Development (.env):**
```bash
DEBUG=True
SECRET_KEY=dev-secret-key
DATABASE_URL=postgresql://bp_user:bp_pass@postgres:5432/bp_db
REDIS_URL=redis://redis:6379/0
ALLOWED_HOSTS=localhost,127.0.0.1
```

**Production (.env.prod):**
```bash
DEBUG=False
SECRET_KEY=super-strong-secret-key
DATABASE_URL=postgresql://user:pass@managed-db:5432/dbname
REDIS_URL=redis://redis:6379/0
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DOMAIN=yourdomain.com
SSL_EMAIL=your-email@domain.com
```

### Django Settings

Django otomatik olarak doğru environment dosyasını seçer:
- **DJANGO_ENV=development** → `.env` okur (varsayılan)
- **DJANGO_ENV=staging** → `.env.staging` okur
- **DJANGO_ENV=production** → `.env.prod` okur

### Nginx Konfigürasyonu

```bash
# nginx/default.conf dosyasını düzenleyerek:
# - Domain ayarları
# - SSL konfigürasyonu
# - Rate limiting
# - Security headers
# gibi ayarları değiştirebilirsiniz
```

## 🔍 Troubleshooting

### Servislerin Çalışmadığı Durumlar

```bash
# Port zaten kullanımda
make down && make up

# Permission hatası
sudo chown -R $USER:$USER .

# Docker disk alanı dolmuş
docker system prune -f

# Container'lar çalışmıyor
docker ps -a
docker logs <container_name>
```

### Database Bağlantı Sorunları

```bash
# Development database problemi
make logs-backend
docker exec bp_postgres psql -U bp_user -d bp_db -c "\l"

# Production database problemi
make logs-prod | grep -i database
# .env.prod'da DATABASE_URL kontrolü
```

### SSL Sorunları

```bash
# SSL container çalışmıyor
make ssl-container-status
make logs-ssl

# Sertifika alınamıyor
# DNS doğru yönlendirildi mi kontrol et:
nslookup yourdomain.com
dig yourdomain.com

# Port 80 açık mı kontrol et:
curl -I http://yourdomain.com/.well-known/acme-challenge/

# SSL container'ı yeniden başlat:
make ssl-container-restart
```

### Performance Sorunları

```bash
# Container resource kullanımı
docker stats

# Disk kullanımı
docker system df

# Log dosyaları çok büyümüş
docker system prune -f
```

## 🚀 Development Workflow

### Yeni Feature Geliştirme

```bash
# 1. Development ortamını başlat
make up

# 2. Yeni Django app oluştur
make shell
python manage.py startapp myapp

# 3. Model değişiklikleri
make makemigrations
make migrate

# 4. Test et
make test

# 5. Production'a deploy et
git push origin main
# VPS'te: git pull && make restart-prod
```

### Development İşlemleri

```bash
# Migration oluştur
make makemigrations

# Migration uygula
make migrate          # Development
make migrate-prod     # Production
make migrate-staging  # Staging

# Static files topla
make collectstatic    # Development
make collectstatic-prod     # Production
make collectstatic-staging  # Staging

# Database shell
make shell-db         # Development PostgreSQL shell

# Django shell
make shell
python manage.py shell
```

### Celery Task Geliştirme

```python
# backend/apps/myapp/tasks.py
from celery import shared_task

@shared_task
def my_background_task(param):
    # Background task logic
    return "Task completed"
```

```bash
# Celery loglarını izle
make logs-celery

# Task'ı test et
make shell
>>> from apps.myapp.tasks import my_background_task
>>> my_background_task.delay("test")
```

## 📊 Monitoring & Logs

### Log İzleme

```bash
# Tüm servis logları
make logs              # Development
make logs-prod         # Production
make logs-staging      # Staging

# Specific servis logları
make logs-backend      # Django backend
make logs-celery       # Celery worker & beat
make logs-ssl          # SSL certificate management
```

### Health Checks

```bash
# Service health kontrolü
curl http://localhost/health/       # Development
curl https://yourdomain.com/health/ # Production

# Container durumları
docker ps
docker stats

# SSL sertifika durumu
make ssl-container-status
```

### Performance Monitoring

```bash
# Container resource kullanımı
docker stats

# Database query analizi
make shell
python manage.py shell
>>> from django.db import connection
>>> connection.queries

# Redis cache durumu
docker exec bp_redis redis-cli info
```

## 🛡️ Güvenlik

### Production Güvenlik

- ✅ **HTTPS Zorunlu** - Tüm HTTP trafiği HTTPS'e yönlendirilir
- ✅ **Security Headers** - XSS, CSRF, Clickjacking koruması
- ✅ **Rate Limiting** - API abuse koruması
- ✅ **HSTS** - HTTP Strict Transport Security
- ✅ **Secure Cookies** - SSL-only cookies

### SSL Güvenliği

```bash
# SSL sertifika bitiş tarihi kontrolü
openssl s_client -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -enddate

# SSL Labs test
# https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com

# Security headers kontrolü
curl -I https://yourdomain.com | grep -i 'strict-transport\|x-frame\|x-content'
```

### Database Güvenliği

- ✅ **Managed Database** - Professional backup & monitoring
- ✅ **SSL Connection** - Database bağlantısı şifreli
- ✅ **Environment Variables** - Hassas bilgiler .env dosyasında
- ✅ **User Permissions** - Minimal database permissions

## 🔄 Backup Strategy

### Database Backup

```bash
# Development database backup
docker exec bp_postgres pg_dump -U bp_user bp_db > backup.sql

# Production database backup (managed DB provider'dan)
# Otomatik backup'lar genelde managed DB service'inde vardır
```

### SSL Certificate Backup

```bash
# SSL sertifikalarını yedekle
tar -czf ssl-backup-$(date +%Y%m%d).tar.gz nginx/ssl/

# Container'dan backup al
docker exec bp_certbot tar -czf /tmp/ssl-backup.tar.gz -C /etc/letsencrypt .
docker cp bp_certbot:/tmp/ssl-backup.tar.gz ./ssl-backup.tar.gz
```

### Application Backup

```bash
# Code backup (Git repository zaten backup)
git push origin main

# Media files backup
tar -czf media-backup-$(date +%Y%m%d).tar.gz backend/media/
```

## 🌟 Best Practices

### Development Best Practices

1. **Environment dosyalarını commit etmeyin** (.env, .env.prod)
2. **Migration dosyalarını commit edin** (version control)
3. **Test yazın** (make test komutu ile çalışan)
4. **Code quality** (linter, formatter kullanın)
5. **Docker image'ları güncel tutun** (security updates)

### Production Best Practices

1. **Managed database kullanın** (DigitalOcean, AWS RDS, etc.)
2. **SSL otomatik yenileme** (container yaklaşımı önerilen)
3. **Monitoring setup** (logs, health checks, alerts)
4. **Regular backup** (database, SSL certificates, media)
5. **Security updates** (Docker images, dependencies)

### Deployment Best Practices

1. **Staging'de test edin** (production'a göndermeden önce)
2. **Zero-downtime deployment** (blue-green deployment)
3. **Rollback planı** (git tag'ler, database backup)
4. **Environment consistency** (dev/staging/prod aynı teknolojiler)
5. **Infrastructure as Code** (Docker Compose files)

## 🤝 Contributing

1. Fork repository
2. Feature branch oluştur (`git checkout -b feature/amazing-feature`)
3. Development ortamında test et (`make test`)
4. Commit et (`git commit -m 'Add amazing feature'`)
5. Push et (`git push origin feature/amazing-feature`)
6. Pull Request oluştur

## 📚 Daha Fazla Bilgi

### Dokümantasyon
- [Django Documentation](https://docs.djangoproject.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Celery Documentation](https://docs.celeryq.dev/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

### Community
- GitHub Issues - Bug reports & feature requests
- GitHub Discussions - Community support
- Stack Overflow - Technical questions

---

**🎯 Bu boilerplate sayesinde dakikalar içinde production-ready Django projesi ayağa kaldırabilirsiniz!**

*Development'tan production'a kadar tüm ortamlar Docker ile standardize edilmiş, SSL otomatik yönetiliyor, ve deployment process optimize edilmiş durumda.*