# 🔐 Production Database & Monitoring Access Guide

Production ortamında veritabanı ve monitoring tool'larına güvenli erişim rehberi.

## ⚠️ Neden pgAdmin ve Flower Production'da Kapalı?

### pgAdmin Güvenlik Riskleri
- **Web-based access**: Internet'e açık database yönetimi
- **Attack surface**: Brute force ve credential stuffing saldırıları
- **Full privileges**: DROP DATABASE dahil tüm yetkiler
- **Data exposure**: Müşteri verileri, API keys, business logic

### Flower Güvenlik Riskleri
- **Task details**: Celery task arguments (sensitive data içerebilir)
- **System metrics**: Performance data ve system information
- **Error exposure**: Stack traces ve code paths
- **Business logic**: Task flow ve application architecture

### Real-world Scenario
```bash
# Riskli: Web UI'lar açık
http://YOUR_VPS_IP:5051  # pgAdmin → Internet'e açık ❌
http://YOUR_VPS_IP:5555  # Flower → Internet'e açık ❌

# Güvenli: SSH tunnel
localhost:5432  # Database → Sadece local erişim ✅
localhost:5555  # Flower → Sadece local erişim ✅
```

---

## 🚀 Güvenli Access Yöntemleri

### 1. SSH Tunnel (Önerilen) 🌟

#### **Staging Database Access:**
```bash
# SSH tunnel oluştur
ssh -L 5432:localhost:5433 root@YOUR_VPS_IP

# pgAdmin'de server ekle:
Host: localhost
Port: 5432
Username: bp_staging_user
Password: [.env.staging'deki şifre]
Database: bp_staging_db
```

#### **Production Database Access:**
```bash
# SSH tunnel oluştur
ssh -L 5432:localhost:5432 root@YOUR_VPS_IP

# pgAdmin'de server ekle:
Host: localhost  
Port: 5432
Username: bp_prod_user
Password: [.env.prod'deki şifre]
Database: bp_prod_db
```

#### **Flower Monitoring Access:**
```bash
# Flower için SSH tunnel
ssh -L 5555:localhost:5555 root@YOUR_VPS_IP

# Browser'da açın:
http://localhost:5555
# Login: admin / [.env'deki FLOWER_PASSWORD]
```

#### **Multiple Tunnels (Aynı Anda):**
```bash
# Database + Flower aynı anda
ssh -L 5432:localhost:5432 -L 5555:localhost:5555 root@YOUR_VPS_IP

# Veya farklı local portlar:
ssh -L 5433:localhost:5432 -L 5556:localhost:5555 root@YOUR_VPS_IP
```

#### **Background'da SSH Tunnel:**
```bash
# Tunnel'ı background'da çalıştır
ssh -f -N -L 5432:localhost:5433 root@YOUR_VPS_IP

# -f: background mode
# -N: no command execution
# Tunnel aktif kaldığı sürece bağlantı var
```

### 2. SSH Key Setup (Önerilen)

#### **Şifresiz SSH Access:**
```bash
# Local'de SSH key oluştur
ssh-keygen -t rsa -b 4096 -C \"your-email@domain.com\"

# Public key'i server'a kopyala
ssh-copy-id root@YOUR_VPS_IP

# Test et
ssh root@YOUR_VPS_IP  # Şifre sormayacak
```

### 3. Multiple Database Access

#### **Farklı Portlar Kullanma:**
```bash
# Staging tunnel
ssh -L 5433:localhost:5433 root@YOUR_VPS_IP

# Production tunnel (aynı anda)
ssh -L 5434:localhost:5432 root@YOUR_VPS_IP

# pgAdmin'de iki farklı server:
# Staging: localhost:5433
# Production: localhost:5434
```

---

## 🛠️ Alternative Access Methods

### 1. CLI Database Access

#### **psql via SSH:**
```bash
# Server'a SSH ile bağlan
ssh root@YOUR_VPS_IP

# PostgreSQL shell
docker exec -it bp_backend_staging python manage.py dbshell

# veya direkt psql
docker exec -it bp_postgres_staging psql -U bp_staging_user -d bp_staging_db
```

#### **Django Shell:**
```bash
# Django ORM ile database işlemleri
ssh root@YOUR_VPS_IP
docker exec -it bp_backend_staging python manage.py shell

# Django shell'de:
from django.contrib.auth.models import User
User.objects.all()
```

### 2. Database Backup & Download

#### **Backup Alma:**
```bash
# Server'da backup al
ssh root@YOUR_VPS_IP
docker exec bp_postgres_staging pg_dump -U bp_staging_user bp_staging_db > backup.sql

# Local'e indir
scp root@YOUR_VPS_IP:/opt/bp/backup.sql ./staging_backup.sql

# Local'de restore et (development'ta test için)
psql -U bp_user -d bp_db < staging_backup.sql
```

### 3. Web-based Alternatives

#### **Adminer (Lightweight Alternative):**
```yaml
# docker-compose.staging.yml'e ekle (sadece gerektiğinde)
adminer:
  image: adminer:4-standalone
  container_name: bp_adminer_staging  
  ports:
    - \"8080:8080\"
  environment:
    ADMINER_DEFAULT_SERVER: postgres
```

**Erişim:** `http://YOUR_VPS_IP:8080` (geçici kullanım için)

---

## 🔐 Security Best Practices

### SSH Security
```bash
# SSH config (~/.ssh/config)
Host bp-staging
    HostName YOUR_VPS_IP
    User root
    Port 22
    IdentityFile ~/.ssh/id_rsa
    LocalForward 5432 localhost:5433

# Kullanım:
ssh bp-staging  # Otomatik tunnel + bağlantı
```

### Database Security Layers
```bash
✅ Network: Private subnet'te database
✅ Firewall: Sadece backend container erişebilir  
✅ Authentication: Strong credentials
✅ Encryption: SSL connections
✅ Monitoring: Query logging
✅ Backup: Encrypted backups
✅ Access: SSH tunnel only
```

### Connection Monitoring
```bash
# Aktif bağlantıları görme
docker exec -it bp_postgres_staging psql -U bp_staging_user -d bp_staging_db -c \"
SELECT datname, usename, application_name, client_addr, state 
FROM pg_stat_activity 
WHERE state = 'active';
\"
```

---

## 🚨 Troubleshooting

### SSH Tunnel Sorunları

**Port zaten kullanımda:**
```bash
# Port kontrolü
lsof -i :5432

# Farklı local port kullan
ssh -L 5433:localhost:5433 root@YOUR_VPS_IP
```

**SSH connection refused:**
```bash
# SSH servisi çalışıyor mu?
systemctl status ssh

# Firewall port 22 açık mı?
ufw status
```

**Database connection failed:**
```bash
# Container çalışıyor mu?
ssh root@YOUR_VPS_IP
docker ps | grep postgres

# Database logları
docker logs bp_postgres_staging
```

### pgAdmin Bağlantı Sorunları

**\"Server doesn't exist\":**
```bash
# SSH tunnel aktif mi?
ps aux | grep ssh

# Doğru port kullanıyor musun?
# Staging: localhost:5433 (tunnel varsa 5432)
# Production: localhost:5432
```

**Authentication failed:**
```bash
# .env dosyasındaki credentials doğru mu?
ssh root@YOUR_VPS_IP
cat .env.staging | grep POSTGRES
```

---

## 📊 Comparison: Access Methods

| Method | Security | Ease of Use | Performance | Use Case |
|--------|----------|-------------|-------------|----------|
| **SSH Tunnel + pgAdmin** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | GUI database management |
| **SSH + CLI (psql)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Quick queries, scripts |
| **Django Shell** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ORM operations, debugging |
| **Database Backup** | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | Data analysis, migration |
| **Web Admin (Adminer)** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Emergency access only |

---

## 🎯 Quick Reference

### Daily Use Commands
```bash
# SSH tunnel başlat
ssh -L 5432:localhost:5433 root@YOUR_VPS_IP

# Background tunnel
ssh -f -N -L 5432:localhost:5433 root@YOUR_VPS_IP

# Tunnel'ı sonlandır
pkill -f \"ssh.*5432:localhost:5433\"

# Database backup
ssh root@YOUR_VPS_IP \"docker exec bp_postgres_staging pg_dump -U bp_staging_user bp_staging_db\" > backup.sql
```

### Emergency Access
```bash
# Hızlı Django shell erişimi
ssh root@YOUR_VPS_IP -t \"docker exec -it bp_backend_staging python manage.py shell\"

# Database shell
ssh root@YOUR_VPS_IP -t \"docker exec -it bp_postgres_staging psql -U bp_staging_user -d bp_staging_db\"
```

---

**💡 Pro Tip:** SSH tunnel'ları alias olarak kaydet:

```bash
# ~/.bashrc veya ~/.zshrc'ye ekle
alias bp-staging-db=\"ssh -L 5432:localhost:5433 root@YOUR_VPS_IP\"
alias bp-prod-db=\"ssh -L 5432:localhost:5432 root@YOUR_VPS_IP\"

# Kullanım:
bp-staging-db  # Tunnel başlar
```

Bu rehber ile production database'ine güvenli erişim sağlayabilirsiniz! 🛡️
