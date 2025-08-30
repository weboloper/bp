# cPanel Deployment Rehberi

Bu proje hem Docker (VPS) hem de cPanel (shared hosting) ile uyumlu.

## 🔄 cPanel'e Deploy Etmek için:

### 1. Dosya Yapısı (cPanel)
```
public_html/
├── passenger_wsgi.py        # Ana dizinde (WSGI entry point)
├── backend/
│   ├── config/
│   ├── manage.py
│   ├── requirements.txt
│   └── .env                 # cPanel için environment
├── static/                  # Collected static files
└── media/                   # Upload edilecek dosyalar
```

### 2. passenger_wsgi.py Mantığı
Mevcut `passenger_wsgi.py` akıllıca şu işleri yapıyor:
- Backend klasörünü Python path'e ekler
- Working directory'yi backend'e değiştirir (.env dosyası için)
- Django WSGI application'ı import eder

### 3. Python App Oluştur (cPanel)
- Python Selector'dan yeni app oluştur
- Python 3.11+ seç
- Domain/subdomain belirle
- App directory'yi public_html olarak ayarla

### 4. Dependencies Yükle
```bash
cd ~/public_html/backend
pip install -r requirements.txt
```

### 5. Environment Setup (.env)
backend/.env dosyası oluştur:
```
DEBUG=False
SECRET_KEY=your-very-strong-secret-key-here
DATABASE_URL=mysql://cpanel_user:password@localhost/cpanel_database

# cPanel MySQL genelde şu formatta:
# DATABASE_URL=mysql://username_dbuser:password@localhost/username_dbname
```

### 6. Database Setup (cPanel MySQL)
- cPanel'de MySQL database oluştur
- User oluştur ve database'e assign et
- Requirements.txt'e mysqlclient ekle:
```
# backend/requirements.txt'e ekle:
mysqlclient==2.1.1
```

### 7. Django Commands
```bash
cd ~/public_html/backend
python manage.py migrate
python manage.py collectstatic
python manage.py createsuperuser
```

### 8. Static Files (cPanel)
.htaccess ile static dosyaları serve et:
```apache
# public_html/.htaccess
RewriteEngine On

# Static files
RewriteRule ^static/(.*)$ /static/$1 [L]
RewriteRule ^media/(.*)$ /media/$1 [L]

# Django app
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ passenger_wsgi.py/$1 [QSA,L]
```

## 🚀 Geçiş Stratejileri

### Docker → cPanel Geçiş
1. **Code**: Değişiklik yok! Aynı kod çalışır
2. **Database**: 
   - PostgreSQL → MySQL
   - `pip install mysqlclient`
   - DATABASE_URL güncelle
3. **Environment**: .env dosyasını backend/ klasörüne koyar
4. **Static**: `collectstatic` manuel çalıştır

### cPanel → Docker Geçiş  
1. **Code**: Hiç değişiklik yok
2. **Database**: MySQL → PostgreSQL (data migration)
3. **Environment**: .env ana dizine taşı
4. **Services**: Redis, Celery otomatik çalışır

## 📊 Platform Karşılaştırması

| Feature | Docker (VPS) | cPanel | 
|---------|--------------|--------|
| Django Core | ✅ | ✅ |
| Database | PostgreSQL | MySQL |
| Caching | Redis | ❌ |
| Background Tasks | Celery | ❌ |
| File Uploads | ✅ | ✅ |
| Admin Panel | ✅ | ✅ |
| Custom Domains | ✅ | ✅ |
| SSL | Let's Encrypt | cPanel SSL |
| Cost | $5-20/month | $3-10/month |

## 💡 Hibrit Yaklaşım Önerisi
- **Development**: Docker (tam feature set)
- **Production**: VPS + Docker (full power)
- **Backup/Demo**: cPanel (ucuz, hızlı deployment)

Bu setup sayesinde aynı codebase ile her platformda çalışabilirsin! 🎯
