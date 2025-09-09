# Caddy Klasörü Dosya Durumu

## 🟢 Aktif Dosyalar

Bu dosyalar şu anda kullanılmakta:

- `Caddyfile.dev` - Development environment için (HTTP only)
- `Caddyfile.prod` - Staging ve Production environment'lar için (HTTPS + SSL)

## 📝 Özellikler

### 🏠 Development (Caddyfile.dev)

- **HTTP Only** - SSL/HTTPS devre dışı
- **Static Files**: `/static/*` → `/static` klasöründen serve
- **Media Files**: `/media/*` → `/media` klasöründen serve
- **Health Check**: `/health` → "healthy" response
- **Backend Proxy**: Diğer tüm istekler → `backend:8000`
- **Cache**: Static 30 gün, Media 7 gün

### 🔐 Staging/Production (Caddyfile.prod)

- **Auto HTTPS** - Let's Encrypt SSL otomatik
- **Security Headers** - HSTS, XSS, CSRF koruması
- **Static Files**: Gzip + 1 yıl cache (immutable)
- **Media Files**: 30 gün cache
- **Health Check**: `/health` endpoint
- **Backend Proxy**: Timeout ayarları ile
- **Gzip Compression** - Tüm response'lar için

## 📝 Kullanım

### Development

- `docker-compose.yml` → `Caddyfile.dev` kullanır
- HTTP only: `http://localhost` veya `http://myproject.local`
- Static: `http://localhost/static/`
- Media: `http://localhost/media/`
- Health: `http://localhost/health`

### Staging

- `docker-compose.staging.yml` → `Caddyfile.prod` kullanır
- HTTPS: `https://staging.yourdomain.com`
- Otomatik SSL sertifika yönetimi

### Production

- `docker-compose.prod.yml` → `Caddyfile.prod` kullanır
- HTTPS: `https://yourdomain.com`
- Production optimizasyonları aktif

## 📊 Performans

- **Static Files**: Uzun cache süresi + immutable
- **Gzip**: Otomatik sıkıştırma
- **Security**: Production güvenlik header'ları
- **Timeout**: Backend bağlantı ayarları
