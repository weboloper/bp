# 🩺 Monitoring & Health Checks Guide

Production ortamında sistem sağlığını izleme ve hata takibi rehberi.

## 📊 Monitoring Stack Overview

### ✅ Mevcut Monitoring Tools
```bash
✅ Sentry (Error tracking) - Hazır, aktivasyon gerekli
✅ Built-in Health Endpoint (/health/) - Aktif
✅ Comprehensive Health Scripts - Hazır
✅ Docker Container Monitoring - Aktif
✅ DigitalOcean VPS Monitoring - Otomatik
✅ Flower (Celery monitoring) - Güvenli erişim
✅ Caddy Access Logs - JSON format
✅ Django Debug Toolbar (development) - Aktif
```

### 🎯 Current Setup Yeterliliği
**Bu stack şunlar için yeterli:**
- MVP ve early-stage applications
- <1000 concurrent users  
- Small teams (1-3 developers)
- Simple CRUD operations
- Budget-conscious deployments

---

## 🔴 Sentry Error Tracking

### Setup Status
```python
# ✅ YÜKLÜ: requirements.txt
sentry-sdk[django]==2.15.0

# ✅ CONFIGURED: settings.py
- Django integration ✅
- Celery integration ✅  
- Redis integration ✅
- Environment tracking ✅
- Release tracking ✅

# 🔧 ACTIVATION NEEDED: .env files
SENTRY_DSN=  # Boş - set etmen gerekiyor
```

### Sentry Aktivasyonu

#### **1. Sentry.io'da Proje Oluştur:**
```bash
1. https://sentry.io'ya kaydol (free tier)
2. "Create Project" → Django seç
3. DSN'i kopyala: https://abc123@o123.ingest.sentry.io/456789
```

#### **2. Environment Variables'a Ekle:**
```bash
# .env (development - opsiyonel)
SENTRY_DSN=https://your-dsn@sentry.io/project-id

# .env.staging (önerilen)
SENTRY_DSN=https://your-dsn@sentry.io/project-id
APP_VERSION=1.0.0

# .env.prod (zorunlu)
SENTRY_DSN=https://your-dsn@sentry.io/project-id
APP_VERSION=1.0.0
```

#### **3. Restart & Test:**
```bash
# Staging test
make restart-staging

# Production activate
make restart-prod

# Test error gönder
python manage.py shell
>>> 1/0  # Bu error Sentry'ye gidecek
```

### Sentry Features
```bash
🔍 Automatic error capturing
👤 User context tracking  
📊 Performance monitoring
🚀 Release tracking
📧 Email/Slack notifications
🔗 Integration with GitHub/Jira
📈 Error trends and analytics
```

---

## 🩺 Health Check System

### 1. Built-in Health Endpoint

#### **Endpoint Details:**
```bash
URL: /health/
Method: GET
Authentication: Public (no auth required)
```

#### **Response Format:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-09T17:30:00Z",
  "environment": "production",
  "debug": false,
  "python_version": "3.11.5", 
  "django_version": "5.2.5"
}
```

#### **Usage Examples:**
```bash
# Development
curl http://localhost/health/

# Staging
curl https://staging.yourdomain.com/health/

# Production
curl https://yourdomain.com/health/

# Check status only
curl -s https://yourdomain.com/health/ | jq -r '.status'
```

### 2. Comprehensive Health Check Script

#### **Script Location:** `./scripts/health_check.sh`

#### **Features:**
```bash
🌐 Django Application status
🗄️ Database connection test
📁 Static files serving test
🔄 Celery workers status (via SSH tunnel)
🔐 SSL certificate validation
⚡ Response time measurement
📊 Detailed health information
```

#### **Usage:**
```bash
# Make script executable & run
chmod +x scripts/health_check.sh

# Check different environments
./scripts/health_check.sh development
./scripts/health_check.sh staging
./scripts/health_check.sh production

# Or use Makefile shortcuts
make health           # Development
make health-staging   # Staging
make health-prod      # Production
```

#### **Sample Output:**
```bash
🩺 BP Health Check - production Environment
===============================================
🌐 Django Application: ✅ HEALTHY
🗄️  Database Connection: ✅ CONNECTED
📁 Static Files: ✅ SERVING
🔄 Celery Workers: ⚠️  SSH TUNNEL REQUIRED
🔐 SSL Certificate: ✅ VALID (Expires: Dec 15 00:00:00 2025 GMT)
⚡ Response Time: ✅ FAST (0.234s)

📊 Detailed Health Info:
{
  "status": "healthy",
  "timestamp": "2025-09-09T17:30:00Z",
  "environment": "production",
  "debug": false,
  "python_version": "3.11.5",
  "django_version": "5.2.5"
}

🎯 Quick Commands:
   Health:   curl https://yourdomain.com/health/
   Home:     curl https://yourdomain.com/
   Admin:    https://yourdomain.com/admin/
   Flower:   ssh -L 5555:localhost:5555 root@YOUR_VPS_IP

✅ Health check completed!
```

### 3. Docker Container Health Check

#### **Script Location:** `./scripts/docker_health.sh`

#### **Features:**
```bash
📦 Container status overview
💾 Resource usage (CPU, Memory, Network)
🔍 Individual service health
📊 Container logs (last 5 lines)
🎯 Quick management commands
```

#### **Usage:**
```bash
# Make script executable & run
chmod +x scripts/docker_health.sh

# Check different environments
./scripts/docker_health.sh development
./scripts/docker_health.sh staging
./scripts/docker_health.sh production

# Or use Makefile shortcuts
make docker-health         # Development
make docker-health-staging # Staging
make docker-health-prod    # Production
```

#### **Sample Output:**
```bash
🐳 Docker Container Health Check - production
=================================================

📦 Container Status:
NAME                 IMAGE               STATUS
bp_backend           bp_backend:latest   Up 2 hours
bp_caddy             caddy:2-alpine      Up 2 hours  
bp_redis             redis:7-alpine      Up 2 hours
bp_celery            bp_backend:latest   Up 2 hours
bp_celery_beat       bp_backend:latest   Up 2 hours

💾 Container Resources:
CONTAINER        CPU %     MEM USAGE / LIMIT     NET I/O
bp_backend       2.50%     180MiB / 512MiB       1.2kB / 890B
bp_caddy         0.01%     12MiB / 512MiB        2.3kB / 1.8kB
bp_redis         0.05%     25MiB / 512MiB        456B / 123B

🔍 Service Health:
   backend: ✅ RUNNING
   postgres: ✅ RUNNING
   redis: ✅ RUNNING
   caddy: ✅ RUNNING
   celery: ✅ RUNNING
   celery-beat: ✅ RUNNING

📊 Container Logs (last 5 lines):
=================================
[Shows recent logs for each service]
```

---

## 📊 Additional Monitoring Tools

### 1. DigitalOcean VPS Monitoring

#### **Automatic Metrics:**
```bash
📊 CPU Usage
💾 Memory Usage
💿 Disk Usage
🌐 Network Traffic (Bandwidth)
🔥 Load Average
⚡ Network I/O
```

#### **Access:**
```bash
1. DigitalOcean Dashboard
2. Select your droplet
3. "Monitoring" tab
4. Real-time + historical graphs
```

### 2. Flower (Celery Monitoring)

#### **Access via SSH Tunnel:**
```bash
# Create SSH tunnel
ssh -L 5555:localhost:5555 root@YOUR_VPS_IP

# Access Flower
http://localhost:5555
# Login: admin / [FLOWER_PASSWORD from .env]
```

#### **Flower Metrics:**
```bash
🔄 Active tasks
👥 Worker status & performance
📈 Task success/failure rates
⏱️ Task execution times
📊 Queue lengths
🔍 Task arguments & results
📉 Historical performance data
```

### 3. Caddy Access Logs

#### **Log Format:** JSON structured logs

#### **Viewing Logs:**
```bash
# Real-time logs
make logs-caddy

# Recent logs
docker logs bp_caddy --tail 50

# Follow logs
docker logs bp_caddy -f

# Filter by status codes
docker logs bp_caddy 2>&1 | grep "status\":404"
```

#### **Sample Log Entry:**
```json
{
  "ts": 1641234567.890,
  "request": {
    "method": "GET",
    "uri": "/health/",
    "proto": "HTTP/2.0"
  },
  "common_log": "1.2.3.4 - - [04/Jan/2025:12:34:56 +0000] \"GET /health/ HTTP/2.0\" 200 156",
  "duration": 0.123,
  "status": 200,
  "size": 156
}
```

---

## 🚨 Health Check Automation

### 1. Cron Job Health Checks

#### **Setup Automated Health Checks:**
```bash
# Create cron job for regular health checks
crontab -e

# Add this line for every 5 minutes check:
*/5 * * * * /opt/bp/scripts/health_check.sh production >> /var/log/bp-health.log 2>&1
```

### 2. Uptime Monitoring (External)

#### **Free External Services:**
```bash
🔍 UptimeRobot.com (Free tier: 50 monitors)
📊 StatusCake.com (Free tier: 10 tests)
⚡ Pingdom.com (Free tier: 1 site)
🌐 Freshping.io (Free tier: 50 checks)
```

#### **Setup Example (UptimeRobot):**
```bash
1. Sign up at UptimeRobot.com
2. Add new monitor:
   - Type: HTTP(s)
   - URL: https://yourdomain.com/health/
   - Keyword: "healthy"
   - Interval: 5 minutes
3. Add notification channels (email, Slack, etc.)
```

### 3. Alert Scripts

#### **Create Alert Script:** `./scripts/alert.sh`
```bash
#!/bin/bash
# Simple alert script

HEALTH_URL="https://yourdomain.com/health/"
SLACK_WEBHOOK="your-slack-webhook-url"

STATUS=$(curl -s $HEALTH_URL | jq -r '.status')

if [ "$STATUS" != "healthy" ]; then
    MESSAGE="🚨 BP Application is unhealthy! Status: $STATUS"
    
    # Send Slack notification
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"$MESSAGE\"}" \
        $SLACK_WEBHOOK
        
    # Send email (if mail configured)
    echo "$MESSAGE" | mail -s "BP Health Alert" admin@yourdomain.com
fi
```

---

## 📈 When to Upgrade Monitoring

### 🟢 Current Stack Sufficient When:
```bash
✅ Single Django application
✅ <100 concurrent users
✅ Small team (1-3 developers)
✅ Simple CRUD operations
✅ MVP/early stage product
✅ Limited budget
```

### 🟡 Consider Upgrading When:
```bash
⚠️ User base > 1000 active users
⚠️ Revenue > $10k/month
⚠️ Team size > 3 developers
⚠️ Multiple microservices
⚠️ SLA commitments
⚠️ Database performance issues
⚠️ Need custom business metrics
```

### 🔴 Upgrade to Prometheus+Grafana When:
```bash
🚨 High-traffic applications (1000+ concurrent)
🚨 Critical business operations
🚨 DevOps team > 2 people
🚨 Downtime costs significant money
🚨 Need advanced alerting automation
🚨 Multiple environments to monitor
🚨 Complex infrastructure (microservices)
```

---

## 🎯 Quick Reference Commands

### Health Check Commands
```bash
# Application health
make health                    # Development
make health-staging           # Staging  
make health-prod             # Production

# Docker health
make docker-health           # Development
make docker-health-staging   # Staging
make docker-health-prod      # Production

# Manual checks
curl https://yourdomain.com/health/
curl -I https://yourdomain.com/static/admin/css/base.css
```

### Monitoring Access
```bash
# Sentry errors
https://sentry.io/organizations/your-org/projects/

# Flower (via SSH tunnel)
ssh -L 5555:localhost:5555 root@YOUR_VPS_IP
http://localhost:5555

# DigitalOcean monitoring
https://cloud.digitalocean.com/droplets/YOUR_DROPLET_ID/monitoring

# Caddy logs
make logs-caddy
docker logs bp_caddy -f
```

### Emergency Commands
```bash
# Quick service restart
make restart-prod

# Check container status
docker ps
docker stats --no-stream

# View recent logs
make logs-prod --tail 50

# Database health
ssh root@YOUR_VPS_IP -t "docker exec -it bp_backend python manage.py dbshell"
```

---

## 💡 Pro Tips

### 1. Health Check Best Practices
```bash
✅ Monitor what breaks, not everything
✅ Set up alerts for critical failures only
✅ Use external uptime monitoring
✅ Keep health checks lightweight
✅ Include business-critical dependencies
✅ Test health checks regularly
```

### 2. Sentry Best Practices
```bash
✅ Set up different projects for each environment
✅ Configure release tracking with deployments
✅ Use custom tags for better filtering
✅ Set up alert rules for critical errors
✅ Monitor performance issues, not just errors
✅ Clean up resolved issues regularly
```

### 3. Log Management
```bash
✅ Use structured logging (JSON)
✅ Include correlation IDs
✅ Set up log rotation
✅ Monitor disk usage
✅ Use log levels appropriately
✅ Don't log sensitive information
```

---

**🎯 Bottom Line:** Başla basit monitoring ile, büyüdükçe scale et. Premature optimization'dan kaçın, gerçek ihtiyaçlara göre monitoring'i geliştir! 📊

Bu rehber ile production ortamında sistem sağlığınızı etkili şekilde izleyebilirsiniz! 🚀
