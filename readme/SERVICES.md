# 🚀 BP Boilerplate Services Guide

BP Django Boilerplate ile birlikte gelen tüm servisler ve nasıl kullanılacağı.

## 📋 Servis Listesi

| Servis | Port | Kullanım | Ortam |
|--------|------|----------|-------|
| **Django Backend** | 8000 | API & Admin | Tümü |
| **PostgreSQL** | 5432/5433 | Database | Dev/Staging |
| **Redis** | 6379/6380 | Cache & Queue | Tümü |
| **Caddy** | 80/443 | Reverse Proxy + SSL | Tümü |
| **pgAdmin** | 5050/5051 | DB Management | Dev/Staging |
| **Flower** | 5555/5556 | Celery Monitoring | Tümü |

---

## 🔧 Core Services

### Django Backend
**Ne yapar:** Ana uygulama servisi - API endpoints, admin panel  
**Port:** 8000 (internal)  
**URL'ler:**
- Development: http://localhost (Caddy proxy)
- Production: https://yourdomain.com (Caddy proxy + SSL)

**Environment Variables:**
```bash
DEBUG=True/False
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://...
STATIC_FILES_HANDLER=caddy  # Yeni!
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

### Caddy Web Server 🌟
**Ne yapar:** Modern reverse proxy, otomatik SSL, static file serving  
**Port:** 80 (HTTP), 443 (HTTPS)  
**Özellikler:**
- ✅ Otomatik Let's Encrypt SSL
- ✅ HTTP to HTTPS redirect  
- ✅ Static files serving (/static/*, /media/*)
- ✅ Security headers (HSTS, XSS Protection)
- ✅ Gzip compression
- ✅ Health checks
- ✅ Zero-config SSL

**Caddy vs Nginx:**
| Özellik | Caddy | Nginx |
|---------|--------|-------|
| SSL Setup | Otomatik ✅ | Manuel ❌ |
| Config | Basit ✅ | Karmaşık ❌ |
| Let's Encrypt | Built-in ✅ | Certbot gerekli ❌ |
| HTTP/2 | Otomatik ✅ | Manuel config ❌ |

**Caddy Dosyaları:**
- `caddy/Caddyfile.dev` - Development (HTTP)
- `caddy/Caddyfile.prod` - Staging/Production (HTTPS)

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

## 🔒 SSL & Security

### Caddy Otomatik SSL 🌟
**Ne yapar:** Tamamen otomatik Let's Encrypt SSL yönetimi  
**Kullanım:** Zero-config SSL - sadece domain ayarla!  
**Ortamlar:** Staging & Production

**Özellikler:**
- ✅ Otomatik sertifika alma (1-2 dakika)
- ✅ Otomatik yenileme (90 günde bir)
- ✅ HTTP to HTTPS redirect
- ✅ Security headers (HSTS, XSS)
- ✅ Wildcard domain desteği
- ✅ Health check built-in

**SSL Setup (Zero Config!):**
1. DNS'i VPS IP'sine yönlendir
2. `.env` dosyasında `DOMAIN` ve `SSL_EMAIL` ayarla
3. `make up-prod` çalıştır
4. 1-2 dakika bekle → SSL hazır! 🎉

**SSL Status Kontrol:**
```bash
# SSL sertifika durumu
curl -I https://yourdomain.com
# "strict-transport-security" header görmelsin

# Caddy SSL logları
make logs-caddy

# Manual SSL check
openssl s_client -connect yourdomain.com:443
```

**vs Certbot (Eskisinden Farkı):**
| Özellik | Caddy | Certbot+Nginx |
|---------|--------|---------------|
| Setup | 0 adım ✅ | 10+ adım ❌ |
| Config | Otomatik ✅ | Manuel ❌ |
| Yenileme | Otomatik ✅ | Cron job ❌ |
| Debugging | Kolay ✅ | Zor ❌ |

---

## 🌐 Environment Specific Services

### Development Servisleri
```bash
make up  # Başlat

# Erişilebilir servisler:
- Django: http://localhost (Caddy proxy)
- pgAdmin: http://localhost:5050
- Flower: http://localhost:5555
- PostgreSQL: localhost:5432
- Static Files: http://localhost/static/
- Media Files: http://localhost/media/
- Health Check: http://localhost/health
```

### Staging Servisleri  
```bash
make up-staging  # Başlat

# Erişilebilir servisler:
- Django: https://staging.yourdomain.com (Auto SSL!)
- pgAdmin: http://localhost:5051
- Flower: http://localhost:5556
- PostgreSQL: localhost:5433
- Static Files: https://staging.yourdomain.com/static/
- Media Files: https://staging.yourdomain.com/media/
```

### Production Servisleri
```bash
make up-prod  # Başlat

# Erişilebilir servisler:
- Django: https://yourdomain.com (Auto SSL!)
- Flower: http://localhost:5555 (authenticated)
- Managed Database: External
- Static Files: https://yourdomain.com/static/ (Cached, Gzipped)
- Media Files: https://yourdomain.com/media/
```

---

## 🔧 Service Management

### Komutlar
```bash
# Tüm servisler
make up / make down / make restart
make logs / make logs-backend / make logs-celery / make logs-caddy

# Specific ortamlar  
make up-prod / make down-prod / make restart-prod
make up-staging / make down-staging / make restart-staging

# Caddy specific
make logs-caddy        # Caddy logları
make logs-caddy-prod   # Production Caddy logları
make logs-caddy-staging # Staging Caddy logları

# Static files
make collectstatic          # Development
make collectstatic-prod     # Production  
make collectstatic-staging  # Staging

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
curl http://localhost/health         # Development
curl https://yourdomain.com/health   # Production (SSL ile)

# Static files test
curl -I http://localhost/static/admin/css/base.css        # Development
curl -I https://yourdomain.com/static/admin/css/base.css  # Production

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
- **Caddy SSL**: Otomatik HSTS, security headers

### Performance
- **Redis**: Memory limit ayarla
- **PostgreSQL**: Managed DB kullan (önerilen)
- **Caddy**: Static files caching + Gzip aktif
- **Celery**: Worker sayısını ayarla

### Static Files Strategy
```bash
# Development
STATIC_FILES_HANDLER=caddy  # Caddy serves static files

# cPanel/Shared Hosting
STATIC_FILES_HANDLER=whitenoise  # Django serves with WhiteNoise

# AWS S3
STATIC_FILES_HANDLER=s3  # AWS S3 CDN
```

### Monitoring
- **Flower**: Task performance izle
- **Sentry**: Error rate izle  
- **pgAdmin**: DB performance izle (staging'de)
- **Caddy Access Logs**: HTTP request'leri izle

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
make logs-caddy

# Kontrol listesi:
# ✅ DNS doğru yönlendirildi mi? (A record)
# ✅ Port 80/443 açık mı?
# ✅ DOMAIN doğru .env'de tanımlı mı?
# ✅ SSL_EMAIL doğru mu?
# ✅ Firewall engel oluyor mu?
```

**Static files 404:**
```bash
# Collectstatic yapıldı mı?
make collectstatic

# Volume mount doğru mu?
docker exec -it caddy_container ls -la /static/

# STATIC_FILES_HANDLER doğru mu?
docker exec -it backend_container python manage.py shell -c "
from django.conf import settings; 
print(settings.STATIC_FILES_HANDLER)
"
```

**HTTP 308 redirect loop:**
```bash
# Development'ta HTTPS zorlanıyor mu?
# Caddyfile.dev dosyasında auto_https off olmalı

# Production'da SSL sertifikası eksik mi?
make logs-caddy
# Let's Encrypt rate limit aştın mı?
```

---

## 📈 Migration from Nginx

### Nginx'den Caddy'ye Geçiş
```bash
# 1. Eski Nginx container'larını durdur
docker stop nginx_container certbot_container

# 2. .env dosyasını güncelle
STATIC_FILES_HANDLER=caddy

# 3. Yeni Caddy compose'u başlat
make up-prod

# 4. SSL otomatik alınacak (1-2 dakika)
# 5. Test et
curl https://yourdomain.com/health
```

### Avantajları
- ✅ SSL setup süresini 15 dakikadan 2 dakikaya düşürür
- ✅ Certbot cron job'larına gerek kalmaz
- ✅ Nginx config karmaşıklığı ortadan kalkar
- ✅ Otomatik HTTP/2, HTTP/3 desteği
- ✅ Built-in security headers

---

*Bu dokümantasyon BP Django Boilerplate v2.1 için hazırlanmıştır. Caddy Web Server entegrasyonu ile!* 🚀