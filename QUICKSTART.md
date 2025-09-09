# ⚡ BP Boilerplate - 5 Dakikada Başla

Django production-ready projenizi 5 dakikada ayağa kaldırın!

## 🎯 Hangi Ortamı Seçeyim?

### 🤔 Durumunu Seç:

| Durum                           | Önerilen Ortam                        | Süre  |
| ------------------------------- | ------------------------------------- | ----- |
| **Yerel geliştirme yapıyorum**  | [Development](#-development-5-dakika) | 5 dk  |
| **Demo göstereceğim**           | [Staging](#-staging-10-dakika)        | 10 dk |
| **Canlıya alacağım**            | [Production](#-production-15-dakika)  | 15 dk |
| **Shared hosting kullanıyorum** | [cPanel](#-cpanel-20-dakika)          | 20 dk |

---

## 💻 Development (5 dakika)

**Ne için:** Yerel geliştirme, API testi, özellik geliştirme

### 1. Projeyi Klonla

```bash
git clone https://github.com/weboloper/bp.git
cd bp
```

### 2. Environment Hazırla

```bash
cp .env.example .env
# .env dosyasını düzenle:
# - SECRET_KEY değiştir (önemli!)
```

### 3. Başlat

```bash
make build  # Docker imajlarını oluştur
make up     # Servisleri başlat
make migrate # Database oluştur
make createsuperuser  # Admin kullanıcısı
```

### 4. Test Et ✅

```bash
# API test:
curl http://localhost/api/

# Admin: http://localhost/admin/
# pgAdmin: http://localhost:5050 (admin@bp.local / admin123)
# Flower: http://localhost:5555
```

**🎉 Development hazır! Kodlamaya başlayabilirsin.**

---

## 🧪 Staging (10 dakika)

**Ne için:** Client demo, test ortamı, entegrasyon testleri

### 1. VPS Hazırla

```bash
# Ubuntu VPS'e bağlan
sudo apt update && sudo apt install docker.io docker-compose git
```

### 2. Projeyi Deploy Et

```bash
git clone https://github.com/weboloper/bp.git
cd bp
```

### 3. Staging Environment

```bash
cp .env.staging.example .env.staging
# .env.staging düzenle:
# - DOMAIN=staging.yourdomain.com
# - SSL_EMAIL=your-email@domain.com
# - SECRET_KEY değiştir
```

### 4. DNS Ayarla

```bash
# Domain'ini VPS IP'sine yönlendir:
# staging.yourdomain.com -> VPS_IP_ADDRESS
```

### 5. Staging Başlat

```bash
make build-staging
make up-staging
make migrate-staging
make createsuperuser-staging
```

### 6. SSL Otomatik Alınıyor! 🔐

Caddy otomatik Let's Encrypt SSL sertifikası alacak. DNS doğru ayarlandıysa 1-2 dakika içinde HTTPS aktif olur.

### 7. Test Et ✅

```bash
# HTTP (Caddy otomatik HTTPS'e yönlendirir):
curl http://staging.yourdomain.com

# HTTPS test:
curl https://staging.yourdomain.com/api/

# Monitoring:
# pgAdmin: http://VPS_IP:5051
# Flower: http://VPS_IP:5556
```

**🎉 Staging hazır! Client'a demo gösterebilirsin.**

---

## 🚀 Production (15 dakika)

**Ne için:** Canlı sistem, gerçek kullanıcılar

### 1. VPS + Database Seçimi

```bash
# 1. Ubuntu VPS kur (önerilen: 2GB+ RAM)
# 2. Database seçimi:
#    Option A: DigitalOcean/AWS'de managed PostgreSQL oluştur
#    Option B: Container PostgreSQL kullan (basit)
```

### 2. Production Environment

```bash
cp .env.prod.example .env.prod
# .env.prod düzenle:
# - DEBUG=False
# - SECRET_KEY=super-güçlü-key

# Database seçimine göre:
# Option A (Managed DB): DATABASE_URL=postgresql://managed-db-url
# Option B (Container): PostgreSQL variables'ları uncomment et

# - DOMAIN=yourdomain.com
# - SSL_EMAIL=admin@yourdomain.com
# - FLOWER_PASSWORD=güvenli-şifre
```

### 3. DNS + SSL

```bash
# Domain'i VPS'e yönlendir:
# yourdomain.com -> VPS_IP_ADDRESS
# www.yourdomain.com -> VPS_IP_ADDRESS (opsiyonel)
```

### 4. Production Deploy

```bash
make build-prod

# Database seçimine göre:
make up-prod           # Managed DB için
make up-prod-postgres  # Container PostgreSQL için

make migrate-prod
make createsuperuser-prod
make collectstatic-prod
```

### 5. SSL Otomatik! 🔐

Caddy otomatik olarak:
- ✅ Let's Encrypt SSL sertifikası alır
- ✅ HTTP'den HTTPS'e yönlendirir  
- ✅ Sertifikaları otomatik yeniler
- ✅ Security header'ları ekler

**Hiçbir SSL kurulumu gerekmez!**

### 6. Test Et ✅

```bash
# Production test:
curl https://yourdomain.com/api/

# SSL test:
curl -I https://yourdomain.com
# "strict-transport-security" header görmeli

# Monitoring:
# Admin: https://yourdomain.com/admin/
# Flower: http://VPS_IP:5555 (admin/FLOWER_PASSWORD)
```

**🎉 Production hazır! Canlıdasın!**

---

## 🔧 cPanel (20 dakika)

**Ne için:** Shared hosting, düşük maliyet, basit deployment

### 1. Python App Kur

```bash
# cPanel > Python App > Create Application:
# - Python Version: 3.11+
# - Application Root: public_html
# - Application URL: yourdomain.com
# - Startup File: passenger_wsgi.py
```

### 2. Dosyaları Yükle

```bash
# Projeyi zip olarak indir ve cPanel File Manager ile public_html'e yükle
# veya SSH varsa:
git clone https://github.com/weboloper/bp.git .
```

### 3. MySQL Database Oluştur

```bash
# cPanel > MySQL Databases:
# - Database Name: bp_database
# - User: bp_user
# - Password: güçlü-şifre
# - User'ı database'e assign et
```

### 4. Environment Variables

```bash
# Ana dizine .env oluştur:
DEBUG=False
SECRET_KEY=cpanel-için-güçlü-secret-key
DATABASE_URL=mysql://cpanel_user:şifre@localhost/cpanel_database
STATIC_FILES_HANDLER=whitenoise
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

### 5. Dependencies Kur

```bash
# cPanel Terminal (veya SSH):
source /home/username/virtualenv/public_html/3.11/bin/activate
cd backend
pip install -r requirements.txt
pip install mysqlclient  # MySQL için
```

### 6. Django Setup

```bash
# Database migration:
python backend/manage.py migrate

# Static files (WhiteNoise ile):
python backend/manage.py collectstatic --noinput

# Admin kullanıcısı:
python backend/manage.py createsuperuser
```

### 7. SSL (cPanel)

```bash
# cPanel > SSL/TLS > Let's Encrypt
# - Domain seçin ve "Issue" butonuna tıklayın
# Otomatik SSL sertifikası kurulur
```

### 8. Test Et ✅

```bash
# Site testi:
https://yourdomain.com/admin/
https://yourdomain.com/api/
```

### cPanel Özellikleri:

- **WhiteNoise:** Static files Django içinde serve edilir
- **MySQL:** Shared hosting database
- **Passenger WSGI:** cPanel'in Python app sistemi
- **Minimal Resources:** Redis/Celery yok (shared hosting limiti)
- **SSL:** cPanel Let's Encrypt ile manual

### cPanel vs VPS Karşılaştırması:

```
cPanel (Shared):     VPS (Docker):
✅ Ucuz ($5/ay)      ✅ Güçlü ($20/ay)
✅ Kolay setup       ✅ Full kontrol
✅ MySQL included    ✅ PostgreSQL
❌ Redis yok         ✅ Redis + Celery
❌ Celery yok        ✅ Background tasks
❌ Limited resources ✅ Scalable
✅ Manual SSL        ✅ Otomatik SSL
```

**🎉 cPanel hazır! Shared hosting'de çalışıyor!**

---

## 🔍 Hangi Servisler Çalışıyor?

### Development

```
✅ Django Backend      (http://localhost:8000)
✅ PostgreSQL          (localhost:5432)
✅ Redis               (localhost:6379)
✅ Caddy Reverse Proxy (http://localhost:80)
✅ pgAdmin             (http://localhost:5050)
✅ Flower              (http://localhost:5555)
✅ Celery Worker
✅ Celery Beat
```

### Staging

```
✅ Django Backend      (internal:8000)
✅ PostgreSQL          (container)
✅ Redis               (container)  
✅ Caddy + Auto SSL    (https://staging.domain.com)
✅ pgAdmin             (http://IP:5051)
✅ Flower              (http://IP:5556)
✅ Celery Worker
✅ Celery Beat
✅ Let's Encrypt SSL   (otomatik)
```

### Production

```
✅ Django Backend      (internal:8000)
✅ External PostgreSQL (managed)
✅ Redis               (container)
✅ Caddy + Auto SSL    (https://yourdomain.com)
✅ Flower              (http://IP:5555 - authenticated)
✅ Celery Worker
✅ Celery Beat
✅ Let's Encrypt SSL   (otomatik + yenileme)
❌ pgAdmin             (güvenlik için kapalı)
```

### cPanel

```
✅ Django Backend      (https://yourdomain.com)
✅ MySQL Database      (shared)
✅ WhiteNoise          (static files)
✅ Let's Encrypt SSL   (cPanel manual)
❌ Redis               (shared hosting limiti)
❌ Celery              (shared hosting limiti)
❌ Monitoring          (shared hosting limiti)
❌ Reverse Proxy       (shared hosting limiti)
```

---

## 🆘 Sorun mu Var?

### Hızlı Debug

```bash
# Container durumları
docker ps

# Logları kontrol et
make logs

# Caddy logları
make logs-caddy

# Servisleri yeniden başlat
make down && make up
```

### Yaygın Sorunlar

**Port zaten kullanımda:**

```bash
make down
# Port 80/443 başka servis kullanıyor mu?
sudo netstat -tlnp | grep :80
make up
```

**Database bağlanamıyor:**

```bash
make logs-backend
# .env dosyasında DATABASE_URL kontrol et
```

**SSL sertifikası alınamıyor:**

```bash
make logs-caddy
# Kontrol et:
# 1. DNS doğru yönlendirildi mi?
# 2. Port 80/443 açık mı?
# 3. Domain doğru mu?
```

**Static files çalışmıyor:**

```bash
# Collectstatic yap
make collectstatic

# Caddy static mount kontrol et
docker exec -it caddy_container ls -la /static/
```

---

## 📚 Sonraki Adımlar

### Development'tan sonra:

1. **Kendi modellerini ekle:** `make shell` → `python manage.py startapp myapp`
2. **API endpoint'ler oluştur:** Django REST Framework kullan
3. **Frontend bağla:** Next.js, React, vs.
4. **Test yaz:** `make test`

### Production'dan sonra:

1. **Monitoring ekle:** Sentry DSN aktifleştir
2. **Backup kur:** Database backup stratejisi
3. **CDN ekle:** AWS CloudFront, Cloudflare
4. **CI/CD kur:** GitHub Actions ile deployment

### İleri Seviye:

- **AWS S3:** Static files için (`STATIC_FILES_HANDLER=s3`)
- **Custom Domain:** DNS ayarları
- **Multiple Environment:** Dev/Staging/Prod pipeline
- **Load Balancer:** Çoklu instance

---

## 🎯 Özet

| Ortam           | Setup Süresi | SSL          | Kullanım         | Maliyet  |
| --------------- | ------------ | ------------ | ---------------- | -------- |
| **Development** | 5 dk         | HTTP         | Yerel geliştirme | Ücretsiz |
| **Staging**     | 10 dk        | Otomatik SSL | Demo & Test      | ~$5/ay   |
| **Production**  | 15 dk        | Otomatik SSL | Canlı sistem     | ~$20/ay  |
| **cPanel**      | 20 dk        | Manual SSL   | Shared hosting   | ~$5/ay   |

**Herhangi bir sorun yaşarsan: [SERVICES.md](./SERVICES.md) detaylı rehberine bak!**

---

_Bu hızlı başlangıç rehberi ile BP Boilerplate'i dakikalar içinde kullanmaya başlayabilirsin! 🚀_
