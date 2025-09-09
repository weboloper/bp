# 🚀 BP - Django Docker Boilerplate

**Production-ready Django boilerplate** with Docker, Celery, Redis, PostgreSQL, Caddy, and comprehensive monitoring stack.

> **Perfect for:** API backends, web applications, microservices, MVP projects

## ⚡ Quick Start

Choose your environment and get started in minutes:

| 🎯 Goal | 📋 Environment | ⏱️ Time | 🔗 Guide |
|---------|---------------|---------|----------|
| **Local Development** | Development | 5 min | [Start Here →](#-development) |
| **Client Demo** | Staging | 10 min | [Deploy →](#-staging) |
| **Production Launch** | Production | 15 min | [Go Live →](#-production) |
| **Shared Hosting** | cPanel | 20 min | [Upload →](#-cpanel) |

**🚀 [Quick Start Guide](./QUICKSTART.md) - Get running in 5 minutes!**

---

## 🏗️ What's Included

### 🔧 Core Stack
- **Django 5.2** + **Django REST Framework** - Backend API
- **PostgreSQL 15** - Primary database
- **Redis 7** - Cache & message broker
- **Celery** - Background tasks & scheduling
- **Caddy** - Reverse proxy with auto-SSL
- **Docker Compose** - Multi-environment orchestration
- **Pre-commit Hooks** - Automatic code quality (Black, flake8, isort)

### 📊 Monitoring Stack
- **Sentry** - Error tracking & performance monitoring (ready to activate)
- **Built-in Health Checks** - `/health/` endpoint + comprehensive scripts
- **Flower** - Celery task monitoring (secure SSH access)
- **pgAdmin** - Database management UI (dev/staging)
- **DigitalOcean Monitoring** - VPS metrics (CPU, Memory, Network)
- **Caddy Logs** - Structured JSON access logs
- **Health Check Scripts** - Automated system health validation

### 🔄 Multi-Environment Support
- **Development** - Full local stack with hot reload
- **Staging** - Production-like testing environment
- **Production** - Scalable production deployment
- **cPanel** - Shared hosting compatible

### 🗂️ Static Files Strategies
- **Caddy** - High-performance static serving (VPS)
- **WhiteNoise** - Simple static serving (cPanel)
- **AWS S3** - CDN-ready cloud storage

---

## 🌐 Live Demo

| Environment | URL | Credentials |
|------------|-----|-------------|
| **API Documentation** | `/api/` | - |
| **Django Admin** | `/admin/` | Your superuser |
| **pgAdmin** | `:5050` | admin@bp.local / admin123 |
| **Flower** | `:5555` | - |
| **Health Check** | `/health/` | - |

---

## 💻 Development

**Perfect for:** Local development, API testing, feature development

### Quick Setup
```bash
git clone https://github.com/weboloper/bp.git
cd bp
cp .env.example .env
make build && make up
make migrate && make createsuperuser
```

### Access Services
- **API:** http://localhost/api/
- **Admin:** http://localhost/admin/
- **pgAdmin:** http://localhost:5050
- **Flower:** http://localhost:5555

### Development Commands
```bash
make up                # Start all services
make down              # Stop all services
make logs              # View logs
make shell             # Django shell
make migrate           # Run migrations
make test              # Run tests
make collectstatic     # Collect static files
```

### Code Quality Commands
```bash
make format            # Auto-format code (Black + isort)
make lint              # Run linting (flake8)  
make code-check        # All quality checks
make precommit-install # Setup pre-commit hooks
```

---

## 🧪 Staging

**Perfect for:** Client demos, integration testing, QA environment

### Setup
```bash
# On your VPS
git clone https://github.com/weboloper/bp.git
cd bp
cp .env.staging.example .env.staging
# Edit .env.staging with your domain and settings
make build-staging && make up-staging
make migrate-staging && make createsuperuser-staging
```

### Features
- **Auto-SSL certificates** (Let's Encrypt)
- **Container PostgreSQL** for isolated testing
- **Full monitoring stack** with pgAdmin & Flower
- **Separate ports** (no conflicts with production)

### Access Services
- **API:** https://staging.yourdomain.com/api/
- **Admin:** https://staging.yourdomain.com/admin/
- **pgAdmin:** http://server-ip:5051
- **Flower:** http://server-ip:5556

---

## 🚀 Production

**Perfect for:** Live applications, real users, scalable deployment

### Setup
```bash
# Recommended: Use managed PostgreSQL (DigitalOcean, AWS RDS)
cp .env.prod.example .env.prod
# Configure: DEBUG=False, strong SECRET_KEY, DATABASE_URL, DOMAIN
make build-prod && make up-prod
make migrate-prod && make createsuperuser-prod
make collectstatic-prod
```

### Production Features
- **Auto-SSL certificates** (Let's Encrypt)
- **Managed database** support (recommended)
- **Secured Flower** with authentication
- **Auto-SSL renewal** with Caddy
- **Performance optimized** settings

### Access Services
- **API:** https://yourdomain.com/api/
- **Admin:** https://yourdomain.com/admin/
- **Flower:** http://server-ip:5555 (authenticated)

### Production Commands
```bash
make build-prod        # Build production images
make up-prod           # Start production services
make migrate-prod      # Run production migrations
make collectstatic-prod # Collect static files
make logs-prod         # View production logs
make caddy-certs       # Check SSL certificates
```

---

## 🔧 cPanel

**Perfect for:** Shared hosting, budget-friendly deployment

### Setup
```bash
# Upload files to public_html
# cPanel > Python App > Create Application
# Set environment variables in cPanel
STATIC_FILES_HANDLER=whitenoise
DEBUG=False
DATABASE_URL=mysql://...
```

### Features
- **WhiteNoise** for static files (no Caddy needed)
- **MySQL** database support
- **Simplified deployment** for shared hosting
- **.htaccess** configuration included

---

## 🔒 SSL & Security

### Automatic SSL (VPS/Cloud)
```bash
# SSL certificates managed by Caddy automatically
# Just set DOMAIN and SSL_EMAIL in .env.prod
# HTTPS enabled by default

# Check SSL status
make caddy-certs
make caddy-logs-prod
```

### Security Features
- **Auto-HTTPS** with Caddy
- **Security headers** (HSTS, XSS protection, etc.)
- **Rate limiting** for API endpoints
- **CORS configuration** for frontend integration
- **Secure cookie settings**

---

## 📊 Monitoring & Health Checks

### Comprehensive Monitoring Stack
| Service | Purpose | Status | Access |
|---------|---------|--------|--------|
| **Sentry** | Error tracking & APM | Ready to activate | Configure SENTRY_DSN |
| **Health Endpoint** | Service status | Built-in | `/health/` |
| **Health Scripts** | System validation | Automated | `make health-prod` |
| **Flower** | Celery monitoring | Secure access | SSH tunnel required |
| **pgAdmin** | Database management | Dev/staging | `:5050/:5051` |
| **Caddy Logs** | Access logs | JSON format | `make logs-caddy` |
| **DO Monitoring** | VPS metrics | Automatic | Dashboard |

### Quick Health Check
```bash
# Application health
curl https://yourdomain.com/health/

# Comprehensive check
make health-prod

# Docker containers
make docker-health-prod
```

### Sentry Setup (Error Tracking)
```bash
# 1. Create project at https://sentry.io
# 2. Add DSN to .env files:
SENTRY_DSN=https://your-dsn@sentry.io/project-id

# 3. Restart services
make restart-prod
```

**📊 [Full Monitoring Guide](./MONITORING.md) - Complete monitoring setup & best practices**

### Debug Commands
```bash
# View logs
make logs              # All services
make logs-backend      # Django backend only
make logs-celery       # Celery tasks only
make caddy-logs        # Caddy proxy logs

# Container status
docker ps              # Running containers
docker stats           # Resource usage

# Database access
make shell-db          # PostgreSQL shell (dev)
pgAdmin UI             # Visual database management
```

### Performance Monitoring
- **Flower Dashboard:** Real-time Celery task monitoring
- **pgAdmin:** Database performance and query analysis
- **Docker Stats:** Container resource usage
- **Sentry:** Application performance monitoring (APM)

---

## 🗂️ Static Files Management

Choose the best strategy for your deployment:

```bash
# Set in .env file:
STATIC_FILES_HANDLER=caddy      # VPS with Caddy (recommended)
STATIC_FILES_HANDLER=whitenoise # cPanel/shared hosting
STATIC_FILES_HANDLER=s3         # AWS S3 + CloudFront
```

### Strategy Comparison
| Strategy | Best For | Performance | Setup |
|----------|----------|-------------|-------|
| **Caddy** | VPS/Cloud | ⭐⭐⭐ | Easy |
| **WhiteNoise** | Shared hosting | ⭐⭐ | Easiest |
| **AWS S3** | High traffic | ⭐⭐⭐ | Complex |

---

## 🔧 Environment Configuration

### Environment Files
- `.env.example` → Development & cPanel template
- `.env.prod.example` → Production VPS template
- `.env.staging.example` → Staging environment template

### Key Configuration Options
```bash
# Django Core
DEBUG=True/False
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=domain.com,www.domain.com

# Database
DATABASE_URL=postgresql://user:pass@host:5432/db

# Static Files
STATIC_FILES_HANDLER=caddy|whitenoise|s3

# SSL (Auto with Caddy)
DOMAIN=yourdomain.com
SSL_EMAIL=admin@yourdomain.com

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
FLOWER_PASSWORD=secure-password
```

---

## 🔄 Database Management

### Migration Commands
```bash
# Development
make migrate
make makemigrations

# Production
make migrate-prod

# Staging
make migrate-staging
```

### Database Options
| Environment | Default Database | Alternative |
|------------|------------------|-------------|
| **Development** | Container PostgreSQL | External PostgreSQL |
| **Staging** | Container PostgreSQL | External PostgreSQL |
| **Production** | External PostgreSQL | Container PostgreSQL |
| **cPanel** | Shared MySQL | - |

### Database Access
- **pgAdmin UI:** Visual database management
- **Django Shell:** `make shell` → `python manage.py dbshell`
- **Direct Connection:** Use credentials from .env file

---

## 🏗️ Project Structure

```
bp/
├── backend/                   # Django application
│   ├── config/               # Django settings
│   ├── apps/                 # Your Django apps
│   ├── requirements.txt      # Python dependencies
│   └── Dockerfile           # Backend container
├── caddy/                    # Caddy configuration
│   ├── Caddyfile            # Development config
│   ├── Caddyfile.prod       # Production config (Auto-SSL)
│   └── Dockerfile           # Caddy container
├── docker-compose.yml        # Development services
├── docker-compose.prod.yml   # Production services
├── docker-compose.staging.yml # Staging services
├── .env.example             # Environment template
├── Makefile                 # Easy commands
├── QUICKSTART.md           # 5-minute setup guide
├── SERVICES.md             # Detailed services guide
└── README.md               # This file
```

---

## 🚀 Deployment Strategies

### Cloud Platforms
- **DigitalOcean Droplets** - Simple VPS deployment
- **AWS EC2** - Scalable cloud deployment  
- **Google Cloud Run** - Serverless containers
- **Azure Container Instances** - Managed containers

### Traditional Hosting
- **Shared Hosting** - cPanel with WhiteNoise
- **VPS** - Full Docker stack with Caddy
- **Dedicated Server** - Maximum performance

### Recommended Production Stack
```
🌐 Domain + DNS (Cloudflare)
🔒 SSL (Auto with Caddy)
🖥️  VPS (DigitalOcean Droplet)
🐳 Docker + Docker Compose
🗄️  Managed PostgreSQL (DigitalOcean)
📦 Static Files (Caddy or S3)
📊 Monitoring (Sentry + Flower)
```

---

## 🔧 Customization

### Adding New Django Apps
```bash
make shell
cd /app
python manage.py startapp myapp
```

### Custom Environment Variables
Add to your `.env` file and reference in `settings.py`:
```python
MY_CUSTOM_SETTING = env('MY_CUSTOM_SETTING', default='default_value')
```

### Extending Docker Services
Add new services to `docker-compose.yml`:
```yaml
services:
  myservice:
    image: myimage:latest
    # configuration...
```

---

## 📚 Documentation

- **[🚀 QUICKSTART.md](./QUICKSTART.md)** - Get started in 5 minutes
- **[🔧 SERVICES.md](./SERVICES.md)** - Detailed services documentation  
- **[📊 MONITORING.md](./MONITORING.md)** - Complete monitoring & health checks guide
- **[🔐 DATABASE_ACCESS.md](./DATABASE_ACCESS.md)** - Secure database & monitoring access
- **[🔧 CODE_QUALITY.md](./CODE_QUALITY.md)** - Pre-commit hooks & code quality standards

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Test in development: `make test`
4. Commit changes: `git commit -m 'Add amazing feature'`
5. Push to branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

- **📖 Documentation:** Check [QUICKSTART.md](./QUICKSTART.md) and [SERVICES.md](./SERVICES.md)
- **🐛 Issues:** [GitHub Issues](https://github.com/weboloper/bp/issues)
- **💬 Discussions:** [GitHub Discussions](https://github.com/weboloper/bp/discussions)
- **📧 Email:** support@yourproject.com

---

**🎯 Ready to build something amazing? [Start with the 5-minute guide!](./QUICKSTART.md)**

*BP Boilerplate - From idea to production in minutes, not hours.* 🚀