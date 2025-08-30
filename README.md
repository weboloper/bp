# BP - Django Docker Projesi

Bu proje Django backend ve opsiyonel Next.js frontend ile Docker kullanarak geliştirilmiştir.

## 📁 Proje Yapısı

```
bp/
├── backend/           # Django uygulaması
├── frontend/          # Next.js uygulaması (opsiyonel)
├── nginx/            # Nginx reverse proxy
├── docker-compose.yml               # Backend servisleri
├── docker-compose.frontend.yml     # Frontend servisi
├── .env              # Environment değişkenleri
├── Makefile          # Kolay komutlar
└── README.md
```

## 🚀 Hızlı Başlangıç

### 1. Projeyi klonla
```bash
git clone <repo-url>
cd bp
```

### 2. Environment dosyasını düzenle
```bash
cp .env.example .env
# .env dosyasındaki değerleri düzenle
# Özellikle SECRET_KEY ve veritabanı şifrelerini değiştir
```

### 3. Sadece Backend (Django)
```bash
make up          # Servisleri başlat
make migrate     # Database migration
make createsuperuser  # Admin kullanıcısı oluştur
```

### 4. Backend + Frontend (Django + Next.js)
```bash
make up-frontend  # Frontend ile beraber başlat
```

## 🛠 Kullanılabilir Komutlar

```bash
make help            # Tüm komutları göster
make build           # Docker imajlarını oluştur
make up              # Backend servisleri başlat
make up-frontend     # Frontend + Backend başlat
make down            # Servisleri durdur
make logs            # Logları göster
make shell           # Backend container'a bağlan
make migrate         # Django migration çalıştır
make createsuperuser # Superuser oluştur
```

## 🔧 Servisler

- **Backend**: Django + DRF (Port: 8000)
- **Frontend**: Next.js (Port: 3000) - Opsiyonel
- **Database**: PostgreSQL (Port: 5432)
- **Cache**: Redis (Port: 6379)
- **Queue**: Celery + Celery Beat
- **Proxy**: Nginx (Port: 80, 443)

## 🌐 URL'ler

- Frontend: http://localhost (Nginx üzerinden)
- Backend API: http://localhost/api/
- Django Admin: http://localhost/admin/
- Direct Backend: http://localhost:8000 (development)
- Direct Frontend: http://localhost:3000 (development)

## 🔒 SSL Kurulumu

### Development (Self-signed)
```bash
# nginx/ssl klasöründe
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem
```

### Production (Let's Encrypt)
```bash
# .env dosyasında DOMAIN ve SSL_EMAIL'i ayarla
make ssl-init
```

## 📝 Development

### Django Uygulaması Ekleme
```bash
make shell
cd /app
python manage.py startapp myapp
```

### Frontend Geliştirme
Frontend klasörüne Next.js kurmak için:
```bash
cd frontend
npx create-next-app@latest . --typescript --tailwind --eslint
```

## 🚀 Production Deployment

### VPS'e Deploy
1. `.env` dosyasında `DEBUG=False` yap
2. `SECRET_KEY` değiştir
3. Domain adını ayarla
4. SSL sertifikası al
5. `make prod-up` ile başlat

### cPanel'den VPS'e Geçiş
Bu Docker yapısı sayesinde:
1. Kod değişikliği yapmadan
2. `git clone` + `make up` ile çalışır
3. Veritabanı backup/restore ile veri taşınır

## 🔍 Troubleshooting

### Yaygın Sorunlar
```bash
# Port zaten kullanımda
make down && make up

# Permission hatası
sudo chown -R $USER:$USER .

# Database connection
make shell-db  # PostgreSQL bağlantısını test et
```

### Logları İncele
```bash
make logs           # Tüm servis logları
make logs-backend   # Sadece Django logları
docker-compose logs postgres  # Database logları
```

## 📚 Daha Fazla Bilgi

- [Django Documentation](https://docs.djangoproject.com/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
