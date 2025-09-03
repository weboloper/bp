# 🚀 BP Boilerplate Services Guide

BP Django Boilerplate ile birlikte gelen tüm servisler ve nasıl kullanılacağı.

## 📋 Servis Listesi

| Servis | Port | Kullanım | Ortam |
|--------|------|----------|-------|
| **Django Backend** | 8000 | API & Admin | Tümü |
| **PostgreSQL** | 5432/5433 | Database | Dev/Staging |
| **Redis** | 6379/6380 | Cache & Queue | Tümü |
| **Nginx** | 80/443 | Reverse Proxy | Tümü |
| **pgAdmin** | 5050/5051 | DB Management | Dev/Staging |
| **Flower** | 5555/5556 | Celery Monitoring | Tümü |
| **Certbot** | - | SSL Management | Prod/Staging |

---

## 🔧 Core Services

### Django Backend
**Ne yapar:** Ana uygulama servisi - API endpoints, admin panel  
**Port:** 8000  
**URL'ler:**
- Development: http://localhost:8000
- Production: https://yourdomain.com

**Environment Variables:**
```bash
DEBUG=True/False
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://...
```

### PostgreSQL Database
**Ne yapar:** Ana veritabanı  
**Port:** 5432 (dev), 5433 (staging)  
**Ortamlar:** Development & Staging (Production'da managed DB önerilen)

**Bağlantı:**
```bash
# Development
Host: localhost
Port: 5432
User: bp_user
Password: bp_pass
Database: bp_db

# Staging  
Host: localhost
Port: 5433
User: bp_staging_user
Password: bp_staging_secure_password
Database: bp_staging_db
```

### Redis
**Ne yapar:** Cache ve Celery message broker  
**Port:** 6379 (dev), 6380 (staging)  
**Kullanım:** Session cache, Celery task queue

### Nginx
**Ne yapar:** Reverse proxy, static files, SSL termination  
**Port:** 80 (HTTP), 443 (HTTPS)  
**Özellikler:**
- Static files serving (development'ta)
- SSL certificate management
- Rate limiting
- Security headers

---

## 📊 Monitoring Services

### pgAdmin
**Ne yapar:** PostgreSQL veritabanı yönetim arayüzü  
**Port:** 5050 (dev), 5051 (staging)  
**Kullanım:** Database tablolarını görüntüleme, query çalıştırma

**Erişim:**
- Development: http://localhost:5050
- Staging: http://localhost:5051

**Login Bilgileri:**
```bash
# Development
Email: admin@bp.local
Password: admin123

# Staging
Email: admin@staging.local
Password: staging123
```

**DB Server Ekleme:**
1. pgAdmin'e giriş yap
2. "Add New Server" tıkla
3. Server bilgileri:
   ```
   Name: BP Database
   Host: postgres (container name)
   Port: 5432
   Username: bp_user (dev) / bp_staging_user (staging)
   Password: .env dosyasındaki şifre
   ```

### Flower  
**Ne yapar:** Celery task monitoring ve management  
**Port:** 5555 (dev/prod), 5556 (staging)  
**Kullanım:** Celery worker'ları, task durumları, queue monitoring

**Erişim:**
- Development: http://localhost:5555
- Staging: http://localhost:5556  
- Production: http://localhost:5555 (Basic Auth: admin/FLOWER_PASSWORD)

**Özellikler:**
- Active task'ları görme
- Worker durumları
- Task history
- Task success/failure oranları
- Real-time monitoring

### Sentry
**Ne yapar:** Error tracking ve performance monitoring  
**Kullanım:** Production hata yakalama, debug bilgileri  
**Setup:** `.env` dosyasında `SENTRY_DSN` aktifleştir

**Özellikler:**
- Automatic error capturing  
- User context tracking
- Performance monitoring
- Release tracking
- Email/Slack notifications

**Sentry DSN Alma:**
1. https://sentry.io'ya kaydol
2. Yeni proje oluştur (Django seç)  
3. DSN'i kopyala
4. `.env` dosyasına ekle:
   ```bash
   SENTRY_DSN=https://your-dsn@sentry.io/project-id
   ```

---

## 🔒 SSL Services

### Certbot
**Ne yapar:** Let's Encrypt SSL sertifika yönetimi  
**Kullanım:** Otomatik SSL sertifika alma ve yenileme  
**Ortamlar:** Production & Staging

**Özellikler:**
- Otomatik sertifika alma
- 12 saatte bir yenileme kontrolü  
- Nginx ile entegrasyon
- Health check monitoring

**SSL Komutları:**
```bash
# SSL durumu kontrol
make ssl-container-status

# SSL logları
make logs-ssl

# Manuel yenileme
make ssl-container-manual-renew
```

---

## 🌐 Environment Specific Services

### Development Servisleri
```bash
make up  # Başlat

# Erişilebilir servisler:
- Django: http://localhost:8000
- pgAdmin: http://localhost:5050
- Flower: http://localhost:5555
- PostgreSQL: localhost:5432
```

### Staging Servisleri  
```bash
make up-staging  # Başlat

# Erişilebilir servisler:
- Django: https://staging.yourdomain.com
- pgAdmin: http://localhost:5051
- Flower: http://localhost:5556
- PostgreSQL: localhost:5433
```

### Production Servisleri
```bash
make up-prod  # Başlat

# Erişilebilir servisler:
- Django: https://yourdomain.com
- Flower: http://localhost:5555 (authenticated)
- Managed Database: External
```

---

## 🔧 Service Management

### Komutlar
```bash
# Tüm servisler
make up / make down / make restart
make logs / make logs-backend / make logs-celery

# Specific ortamlar  
make up-prod / make down-prod / make restart-prod
make up-staging / make down-staging / make restart-staging

# Monitoring
make logs-ssl          # SSL logları
make logs-staging-ssl  # Staging SSL logları

# Database
make shell-db          # PostgreSQL shell (dev)
make migrate           # Dev migration
make migrate-prod      # Production migration
make migrate-staging   # Staging migration
```

### Health Checks
```bash
# Service durumları
docker ps

# Health check'ler
curl http://localhost/health/        # Development
curl https://yourdomain.com/health/  # Production

# Database bağlantısı
make shell
python manage.py dbshell
```

---

## ⚠️ Production Notları

### Güvenlik
- **pgAdmin**: Production'da kullanma, external tool kullan
- **Flower**: Basic authentication ile korumalı
- **Sentry**: Production'da mutlaka aktif et
- **SSL**: Certbot otomatik yeniliyor

### Performance
- **Redis**: Memory limit ayarla
- **PostgreSQL**: Managed DB kullan (önerilen)
- **Nginx**: Static files caching aktif
- **Celery**: Worker sayısını ayarla

### Monitoring
- **Flower**: Task performance izle
- **Sentry**: Error rate izle  
- **pgAdmin**: DB performance izle (staging'de)
- **Logs**: `make logs-prod` ile sistem logları

---

## 🚨 Troubleshooting

### Yaygın Sorunlar

**Servis başlamıyor:**
```bash
docker ps -a
docker logs <container_name>
make down && make up
```

**Database bağlantısı yok:**
```bash
make logs-backend
# .env dosyasında DATABASE_URL kontrolü
```

**Celery task'lar çalışmıyor:**
```bash
make logs-celery
# Redis bağlantısını kontrol et
# Flower'da worker durumu kontrol et
```

**SSL sertifikası alınamıyor:**
```bash
make logs-ssl
# DNS'in doğru yönlendirildiğini kontrol et
# Port 80'in açık olduğunu kontrol et
```

---

*Bu dokümantasyon BP Django Boilerplate v2.0 için hazırlanmıştır.*