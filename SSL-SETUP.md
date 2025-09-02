# 🔒 SSL Kurulum ve Yönetim Rehberi

BP Django boilerplate projesi için SSL sertifikası kurulumu ve yönetimi. **SSL artık ana compose dosyalarına entegre edilmiştir** ve **Certbot Container yaklaşımı** kullanılmaktadır.

## 🚀 SSL Nasıl Çalışır?

**✅ Certbot Container ana compose dosyalarında entegre:**

- `docker-compose.prod.yml` → `certbot` servisi (production SSL)
- `docker-compose.staging.yml` → `certbot-staging` servisi (staging SSL)

## 📋 SSL Yaklaşımı

### 🎯 Certbot Container Yaklaşımı (Varsayılan)

Bu projede **Certbot Container** yaklaşımı kullanılmaktadır:

| Özellik              | Certbot Container                    |
| -------------------- | ------------------------------------ |
| **Kurulum**          | ✅ Otomatik (ana compose dosyasında) |
| **Kaynak Kullanımı** | ~15MB RAM (sürekli çalışır)          |
| **Güvenilirlik**     | ✅ Docker ecosystem entegrasyonu     |
| **Monitoring**       | ✅ Docker logs ile kolay             |
| **Yenileme**         | ✅ 12 saatte bir otomatik kontrol    |
| **Maintenance**      | ✅ Tamamen otomatik                  |

---

## 🐳 Certbot Container SSL Kurulumu

**SSL container'ı artık ana compose dosyalarında entegre - ayrı dosya gereksiz!**

### Production SSL Kurulumu

#### **1. Environment Hazırlığı**

```bash
# Production environment dosyasını oluştur
cp .env.prod.example .env.prod

# .env.prod dosyasını düzenle:
nano .env.prod
```

**Gerekli ayarlar (.env.prod):**

```bash
# SSL Ayarları (ZORUNLU)
DOMAIN=yourdomain.com
SSL_EMAIL=your-email@domain.com

# Django Ayarları
DEBUG=False
SECRET_KEY=super-guclu-secret-key-buraya
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# External Database
DATABASE_URL=postgresql://user:pass@your-managed-db-host:5432/dbname
```

#### **2. Production Deployment**

```bash
# Production servisleri başlat (Certbot container otomatik dahil)
make build-prod
make up-prod

# İlk deployment ise:
make migrate-prod
make createsuperuser-prod

# Certbot container otomatik sertifika almaya çalışacak
# Domain DNS'i sunucuya yönlendirdiğinizden emin olun!
```

#### **3. SSL Durumunu Kontrol Et**

```bash
# SSL container loglarını izle
make logs-ssl

# Container durumunu kontrol et
make ssl-container-status

# Sertifika durumunu kontrol et
docker exec bp_certbot certbot certificates
```

#### **4. HTTPS Yönlendirmesini Aktifleştir**

```bash
# HTTP -> HTTPS yönlendirmesini aç
make ssl-enable-https

# Nginx'i yeniden başlat
make restart-prod

# Test et
curl -I https://yourdomain.com
```

### Staging SSL Kurulumu

#### **1. Staging Environment**

```bash
# Staging environment dosyasını oluştur
cp .env.staging.example .env.staging

# .env.staging dosyasını düzenle:
nano .env.staging
```

**Gerekli ayarlar (.env.staging):**

```bash
# SSL Ayarları (Test sertifikası için)
DOMAIN=staging.yourdomain.com
SSL_EMAIL=your-email@domain.com

# Diğer ayarlar...
DEBUG=True
ALLOWED_HOSTS=staging.yourdomain.com,localhost
```

#### **2. Staging Deployment**

```bash
# Staging servisleri başlat (Certbot container otomatik dahil)
make build-staging
make up-staging

# İlk deployment ise:
make migrate-staging
make createsuperuser-staging

# Staging Certbot container test sertifikası alır (--staging flag ile)
```

#### **3. Staging SSL Kontrol**

```bash
# Staging SSL container loglarını izle
make logs-staging-ssl

# Test sertifikasını kontrol et
curl -k -I https://staging.yourdomain.com
# (-k flag gerekli, çünkü test sertifikası browser'da güvenilmez görünür)
```

### 🔄 Certbot Container Yönetimi

```bash
# Container durumu
make ssl-container-status              # Tüm SSL container'ları

# Logları görüntüle
make logs-ssl                          # Production SSL logları
make logs-staging-ssl                  # Staging SSL logları

# Container yeniden başlat
make ssl-container-restart             # Production container
make ssl-container-restart-staging     # Staging container

# Manuel yenileme
make ssl-container-manual-renew        # Production manuel yenileme
make ssl-container-manual-renew-staging # Staging manuel yenileme
```

### 📊 Certbot Container Otomatik Yenileme

**SSL container'ları 12 saatte bir otomatik kontrol:**

1. Sertifika süresini kontrol eder (30 gün kaldıysa yeniler)
2. Let's Encrypt'ten yeni sertifika alır
3. Nginx container'ına reload sinyali gönderir
4. Tüm işlemler Docker logs'a kaydedilir
5. Health check mekanizması ile container sağlığı takip edilir

---

## 🕰️ Cron Job Yaklaşımı (Eski - Önerilmez)

**Not:** Bu yaklaşım eski sistemlerle uyumluluk için korunmuştur. Yeni kurulumlar için Certbot Container önerilir.

### Cron Job ile SSL (Manuel)

```bash
# Manuel sertifika alma
make ssl-init

# Cron job kurulumu
make ssl-setup-cron

# Manuel yenileme
make ssl-renew

# Sertifika durumu
make ssl-status
```

**Cron Job dezavantajları:**

- Manual setup gerekli
- Container ecosystem dışında
- Monitoring zorlu
- Traditional server dependency

---

## 🛠 SSL Komutları Referansı

### **Certbot Container Komutları (Ana Yaklaşım)**

```bash
# Container durumu ve yönetim
make ssl-container-status                     # Tüm SSL container durumu
make ssl-container-restart                    # Production SSL container restart
make ssl-container-restart-staging           # Staging SSL container restart

# Loglar ve monitoring
make logs-ssl                                 # Production SSL container logları
make logs-staging-ssl                         # Staging SSL container logları

# Manuel yenileme
make ssl-container-manual-renew              # Production manuel yenileme
make ssl-container-manual-renew-staging      # Staging manuel yenileme
```

### **Legacy SSL Komutları (Eski - Sadece uyumluluk)**

```bash
# Sertifika yönetimi
make ssl-init                                 # İlk SSL sertifikası al
make ssl-init-staging                         # Staging SSL sertifikası al (test)
make ssl-renew                                # Manuel SSL yenileme
make ssl-status                               # Sertifika durumunu göster
make ssl-check-expiry                         # Bitiş tarihini kontrol et
make ssl-test-renewal                         # Yenileme testini çalıştır

# Cron job yönetimi
make ssl-setup-cron                           # Otomatik yenileme cron job'u kur
```

### **HTTPS Yönetim Komutları (Ortak)**

```bash
make ssl-enable-https                         # HTTPS yönlendirmesini aktifleştir
make ssl-disable-https                        # HTTPS yönlendirmesini kapat
```

---

## 🔍 Sorun Giderme

### **SSL Sertifikası Alınamıyor**

#### Certbot Container için:

```bash
# Container loglarını kontrol et
make logs-ssl

# Container durumunu kontrol et
make ssl-container-status

# DNS kontrolü
nslookup yourdomain.com
dig yourdomain.com

# Port 80 erişilebilirlik kontrolü
curl -I http://yourdomain.com/.well-known/acme-challenge/test

# Container'ı yeniden başlat
make ssl-container-restart
```

### **HTTPS Yönlendirme Çalışmıyor**

```bash
# Nginx konfigürasyonunu kontrol et
docker exec bp_nginx nginx -t

# SSL dosyalarının varlığını kontrol et
ls -la nginx/ssl/live/yourdomain.com/

# Nginx'i yeniden başlat
make restart-prod

# Browser cache temizle ve test et
curl -IL http://yourdomain.com
```

### **SSL Container Çalışmıyor**

```bash
# Container durumu detay
docker ps | grep certbot
docker inspect bp_certbot --format='{{.State.Health.Status}}'

# Container logları detay
docker logs bp_certbot --tail 50

# Container'ı manuel yeniden başlat
docker restart bp_certbot

# Container'ı tamamen yeniden oluştur
make down-prod
make up-prod
```

### **Rate Limit Hatası**

```bash
# Let's Encrypt rate limit: https://letsencrypt.org/docs/rate-limits/

# Staging ile test et (rate limit yok)
make up-staging

# Production container'ında staging mode test
docker exec bp_certbot certbot certonly --webroot --webroot-path=/var/www/certbot --staging -d yourdomain.com --email your-email@domain.com --agree-tos --force-renewal
```

---

## 🚀 Hızlı Başlangıç Özetleri

### Production SSL (Certbot Container - Önerilen)

```bash
# 1. Environment hazırla
cp .env.prod.example .env.prod
# DOMAIN ve SSL_EMAIL'i düzenle

# 2. Production başlat (Certbot container otomatik dahil)
make build-prod && make up-prod

# 3. HTTPS aktifleştir
make ssl-enable-https && make restart-prod

# 4. Test et
curl -I https://yourdomain.com
```

### Staging SSL (Certbot Container)

```bash
# 1. Environment hazırla
cp .env.staging.example .env.staging
# DOMAIN ve SSL_EMAIL'i düzenle

# 2. Staging başlat (Certbot container otomatik dahil)
make build-staging && make up-staging

# 3. Test et (test sertifikası)
curl -k -I https://staging.yourdomain.com
```

---

## 🛡️ Güvenlik Önerileri

### **SSL Konfigürasyonu**

- ✅ TLS 1.2 ve 1.3 kullanın (nginx/default.conf'ta ayarlı)
- ✅ Strong ciphers kullanın
- ✅ HSTS header'ı aktif (nginx/default.conf'ta ayarlı)
- ✅ Security headers mevcut

### **Certbot Container Güvenliği**

- ✅ Minimal image kullanır (certbot/certbot:latest)
- ✅ Read-only file system (sertifika klasörü hariç)
- ✅ Health check mekanizması mevcut
- ✅ Restart policy: unless-stopped
- ✅ Docker network isolasyonu

### **Monitoring**

```bash
# SSL durumu günlük kontrol scripti
#!/bin/bash
DOMAIN="yourdomain.com"
EXPIRY_DATE=$(docker exec bp_certbot openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/cert.pem | cut -d= -f2)
EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_TIMESTAMP=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_TIMESTAMP - $CURRENT_TIMESTAMP) / 86400 ))

echo "SSL sertifikası durumu: $DAYS_LEFT gün kaldı"

if [ $DAYS_LEFT -lt 7 ]; then
  echo "⚠️ SSL sertifikası $DAYS_LEFT gün içinde süresi dolacak!"
fi
```

---

## 📚 İleri Düzey Konfigürasyon

### **Multiple Domain Support**

```bash
# Certbot container için .env.prod'da:
DOMAIN=yourdomain.com,www.yourdomain.com,api.yourdomain.com

# Container otomatik tüm domain'ler için sertifika alacak
```

### **Wildcard SSL Certificate**

```bash
# Wildcard sertifika için DNS challenge gerekli
# Bu özellik şu anda container'da desteklenmiyor
# Manuel approach gerekli:
docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt certbot/certbot \
  certonly --manual --preferred-challenges dns \
  -d "*.yourdomain.com" -d "yourdomain.com" \
  --email your-email@domain.com --agree-tos
```

### **SSL Certificate Backup**

```bash
#!/bin/bash
# Certbot container SSL backup
BACKUP_DIR="/backup/ssl-certificates/$(date +%Y-%m-%d)"
mkdir -p $BACKUP_DIR

# Container'dan backup al
docker exec bp_certbot tar -czf /tmp/ssl-backup.tar.gz -C /etc/letsencrypt .
docker cp bp_certbot:/tmp/ssl-backup.tar.gz "$BACKUP_DIR/ssl-certificates-$(date +%Y%m%d-%H%M%S).tar.gz"

echo "SSL certificates backed up to $BACKUP_DIR"
```

---

## ⚡ Performans İpuçları

### **Certbot Container Optimizasyonu**

- Container sadece 12 saatte bir aktif renewal kontrol yapar
- Health check intervali optimize edilmiş (12h)
- Container restart policy: unless-stopped (minimum restart)
- Minimal resource footprint (~15MB RAM)

### **Docker Network Optimizasyonu**

- Certbot container aynı network'te (bp_network)
- Nginx reload direkt container komunikasyonu
- Volume mount optimize edilmiş

---

## 🎯 Certbot Container vs Cron Job

| Özellik         | Certbot Container ✅    | Cron Job ❌                 |
| --------------- | ----------------------- | --------------------------- |
| **Setup**       | Otomatik (compose ile)  | Manuel konfigürasyon        |
| **Integration** | Docker ecosystem        | System level                |
| **Monitoring**  | Docker logs             | System logs                 |
| **Scaling**     | Container orchestration | Her sunucuda ayrı setup     |
| **Maintenance** | Otomatik                | Manuel                      |
| **Resource**    | ~15MB sürekli           | Minimal (sadece çalışırken) |
| **Reliability** | Docker restart policies | Cron daemon dependency      |

**✅ Sonuç:** Bu projede Certbot Container yaklaşımı kullanılmaktadır ve önerilir.

---

_Bu rehber BP Django Boilerplate projesinin güncel SSL yapılandırması için hazırlanmıştır. SSL Certbot Container yaklaşımı ile ana compose dosyalarına entegre edilmiştir._

## 📝 Changelog

- **v2.0** - SSL Certbot Container ana compose dosyalarına entegre edildi
- **v2.1** - Ayrı SSL compose dosyaları kaldırıldı
- **v2.2** - Certbot Container ana yaklaşım olarak belirlendi
- **v2.3** - Cron Job legacy olarak işaretlendi
- **v2.4** - Makefile komutları Certbot Container için optimize edildi
