# Backup System Documentation

Otomatik backup sistemi kurulum ve kullanım kılavuzu.

## 📋 İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Script'ler](#scriptler)
3. [Kurulum](#kurulum)
4. [Cron Jobs](#cron-jobs)
5. [AWS S3 Kurulumu](#aws-s3-kurulumu)
6. [Test ve Doğrulama](#test-ve-doğrulama)
7. [Sorun Giderme](#sorun-giderme)

---

## Genel Bakış

### Backup Stratejisi

- **PostgreSQL:** Günlük backup, 7 gün sakla
- **Media Files:** Haftalık backup, 30 gün sakla
- **Offsite (AWS S3):** Opsiyonel, günlük/haftalık
- **Health Check:** Günlük kontrol
- **Restore Test:** Aylık otomatik test

### Backup Lokasyonları

```
/opt/backups/
├── postgres/
│   ├── backup_20241021_020000.sql.gz
│   ├── backup_20241022_020000.sql.gz
│   └── ...
└── media/
    ├── media_backup_20241020_030000.tar.gz
    └── ...
```

---

## Script'ler

### 1. backup_db.sh
PostgreSQL veritabanı backup alır.

```bash
# Kullanım
./scripts/backup_db.sh

# Özellikler
- pg_dump ile compressed backup (.sql.gz)
- Eski backupları otomatik temizler (7 gün)
- Backup integrity check (gunzip -t)
- Opsiyonel AWS S3 upload
- Email notification
```

### 2. backup_media.sh
Media dosyaları backup alır.

```bash
# Kullanım
./scripts/backup_media.sh

# Özellikler
- tar.gz ile compressed backup
- Eski backupları otomatik temizler (30 gün)
- Backup integrity check (tar -tzf)
- Opsiyonel AWS S3 upload
```

### 3. check_backup.sh
Backup'ların sağlığını kontrol eder.

```bash
# Kullanım
./scripts/check_backup.sh

# Kontroller
- Backup yaşı (26 saatten eski mi?)
- Backup boyutu (çok küçük mü?)
- Backup bütünlüğü (bozuk mu?)
- Disk alanı (dolu mu?)
```

### 4. test_restore.sh
Otomatik restore testi yapar.

```bash
# Kullanım
./scripts/test_restore.sh

# Test Adımları
- Test database oluşturur
- Latest backup'tan restore eder
- 5 farklı test çalıştırır
- Test database'i temizler
- Production'a DOKUNMAZ
```

### 5. restore_db.sh
Manuel database restore.

```bash
# Kullanım
./scripts/restore_db.sh <backup_file.sql.gz>

# Örnek
./scripts/restore_db.sh /opt/backups/postgres/backup_20241021_020000.sql.gz

# Güvenlik
- Safety backup alır (önce)
- Confirmation ister
- Aktif bağlantıları kapatır
- Verification yapar
```

---

## Kurulum

### 1. Environment Variables

`.env` dosyasını kontrol et:

```bash
# Backup Configuration
POSTGRES_CONTAINER=bp_postgres
POSTGRES_USER=bp_user
POSTGRES_DB=bp_db
BACKUP_DIR=/opt/backups/postgres
BACKUP_RETENTION_DAYS=7

MEDIA_BACKUP_DIR=/opt/backups/media
MEDIA_DIR=./backend/media

# Offsite Backup (Optional)
OFFSITE_BACKUP_ENABLED=false
AWS_S3_BUCKET=
AWS_REGION=eu-central-1

# Notifications (Optional)
BACKUP_NOTIFY_EMAIL=
```

### 2. Dizinleri Oluştur

```bash
# VPS'te
sudo mkdir -p /opt/backups/postgres
sudo mkdir -p /opt/backups/media
sudo chown -R $USER:$USER /opt/backups
```

### 3. Script'leri Test Et

```bash
cd /opt/bp

# PostgreSQL backup test
./scripts/backup_db.sh

# Media backup test
./scripts/backup_media.sh

# Health check test
./scripts/check_backup.sh

# Restore test
./scripts/test_restore.sh
```

---

## Cron Jobs

### Otomatik Backup Kurulumu

```bash
# Crontab düzenle
crontab -e
```

### Önerilen Cron Jobs

```bash
# PostgreSQL Backup - Her gün saat 02:00
0 2 * * * cd /opt/bp && ./scripts/backup_db.sh >> /var/log/backup.log 2>&1

# Media Backup - Her Pazar saat 03:00
0 3 * * 0 cd /opt/bp && ./scripts/backup_media.sh >> /var/log/backup.log 2>&1

# Health Check - Her gün saat 09:00
0 9 * * * cd /opt/bp && ./scripts/check_backup.sh >> /var/log/backup_health.log 2>&1

# Restore Test - Her ayın 1'i saat 04:00
0 4 1 * * cd /opt/bp && ./scripts/test_restore.sh >> /var/log/backup_restore_test.log 2>&1
```

### Alternatif: Tek Script ile

Master script oluştur:

```bash
# scripts/backup_all.sh
#!/bin/bash
cd /opt/bp
./scripts/backup_db.sh
./scripts/backup_media.sh
./scripts/check_backup.sh
```

Cron:
```bash
0 2 * * * /opt/bp/scripts/backup_all.sh >> /var/log/backup.log 2>&1
```

### Cron Log Yönetimi

```bash
# Log rotation için
sudo nano /etc/logrotate.d/backup

# İçerik:
/var/log/backup*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
```

---

## AWS S3 Kurulumu

### 1. AWS CLI Kurulumu

```bash
# AWS CLI kur
pip install awscli

# Veya
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### 2. AWS Credentials

```bash
# AWS configure
aws configure

# Girilen bilgiler:
AWS Access Key ID: YOUR_ACCESS_KEY
AWS Secret Access Key: YOUR_SECRET_KEY
Default region name: eu-central-1
Default output format: json
```

### 3. S3 Bucket Oluştur

```bash
# AWS Console'dan veya CLI ile:
aws s3 mb s3://myproject-backups --region eu-central-1

# Lifecycle policy (opsiyonel - eski backupları otomatik sil)
aws s3api put-bucket-lifecycle-configuration \
  --bucket myproject-backups \
  --lifecycle-configuration file://lifecycle.json
```

lifecycle.json örneği:
```json
{
  "Rules": [
    {
      "Id": "DeleteOldBackups",
      "Status": "Enabled",
      "Prefix": "postgres/",
      "Expiration": {
        "Days": 90
      }
    }
  ]
}
```

### 4. .env Dosyasını Güncelle

```bash
OFFSITE_BACKUP_ENABLED=true
AWS_S3_BUCKET=myproject-backups
AWS_REGION=eu-central-1
```

### 5. Test Et

```bash
# S3 erişimi test et
aws s3 ls s3://myproject-backups/

# Backup'ı S3'e test et
./scripts/backup_db.sh

# S3'te kontrol et
aws s3 ls s3://myproject-backups/postgres/ --recursive
```

---

## Test ve Doğrulama

### İlk Kurulumda Test

```bash
# 1. Manuel backup al
./scripts/backup_db.sh
./scripts/backup_media.sh

# 2. Backup'lar oluştu mu?
ls -lh /opt/backups/postgres/
ls -lh /opt/backups/media/

# 3. Health check
./scripts/check_backup.sh

# 4. Restore test (ÖNCE TEST ENVIRONMENT'TA!)
./scripts/test_restore.sh

# 5. Manuel restore test (opsiyonel)
./scripts/restore_db.sh /opt/backups/postgres/backup_XXXXXX.sql.gz
```

### Aylık Kontrol

```bash
# 1. Backup'lar düzenli alınıyor mu?
ls -lh /opt/backups/postgres/ | tail -10

# 2. Disk doldu mu?
df -h /opt/backups

# 3. Restore testi başarılı mı?
tail -100 /var/log/backup_restore_test.log

# 4. S3'e yükleniyor mu? (eğer aktifse)
aws s3 ls s3://myproject-backups/postgres/ --recursive | tail -10
```

---

## Sorun Giderme

### Backup Alınamıyor

```bash
# Container çalışıyor mu?
docker ps | grep postgres

# Disk dolu mu?
df -h /opt/backups

# Log'lara bak
tail -50 /var/log/backup.log

# Manuel test
cd /opt/bp
./scripts/backup_db.sh
```

### Cron Çalışmıyor

```bash
# Cron servisi çalışıyor mu?
sudo systemctl status cron

# Cron log'larına bak
sudo tail -50 /var/log/syslog | grep CRON

# Script'e execute permission var mı?
chmod +x /opt/bp/scripts/*.sh

# Script'i manuel çalıştır
/opt/bp/scripts/backup_db.sh
```

### S3 Upload Başarısız

```bash
# AWS CLI kurulu mu?
which aws

# AWS credentials doğru mu?
aws s3 ls

# Bucket var mı?
aws s3 ls s3://myproject-backups/

# Log'lara bak
tail -50 /opt/backups/postgres/backup_*.log
```

### Restore Başarısız

```bash
# Backup bozuk mu?
gunzip -t /opt/backups/postgres/backup_XXXXX.sql.gz

# Database bağlantısı var mı?
docker exec bp_postgres psql -U bp_user -d bp_db -c "SELECT 1;"

# Log'lara bak
./scripts/restore_db.sh /opt/backups/postgres/backup_XXXXX.sql.gz
```

---

## Email Notifications

### Postfix Kurulumu (basit)

```bash
# Postfix kur
sudo apt-get install postfix mailutils

# Test et
echo "Test email" | mail -s "Test" your-email@example.com
```

### .env Dosyasını Güncelle

```bash
BACKUP_NOTIFY_EMAIL=your-email@example.com
```

### Test Et

```bash
# Backup script email gönderecek
./scripts/backup_db.sh

# Check script email gönderecek (hata varsa)
./scripts/check_backup.sh
```

---

## Güvenlik Notları

### Backup Dosyaları

- Backup dosyaları hassas veri içerir
- `/opt/backups` dizini sadece root/user erişebilir olmalı
- S3'te encryption kullan (AES-256)
- S3 bucket public olmamalı

### Production Restore

- Restore öncesi mutlaka backup al
- Test environment'ta önce dene
- Production'da dikkatli ol
- Downtime planlama yap

---

## Hızlı Referans

```bash
# Backup al
./scripts/backup_db.sh
./scripts/backup_media.sh

# Kontrol et
./scripts/check_backup.sh

# Restore et
./scripts/restore_db.sh <backup_file>

# Test et
./scripts/test_restore.sh

# Log'lara bak
tail -f /var/log/backup.log

# Cron kontrol
crontab -l
```

---

**Son güncelleme:** 2024-10-21
