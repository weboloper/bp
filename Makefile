.PHONY: help build up up-prod up-staging down logs shell migrate createsuperuser collectstatic collectstatic-prod collectstatic-staging ssl-init ssl-init-staging ssl-renew ssl-status ssl-test-renewal ssl-setup-cron ssl-enable-https ssl-disable-https ssl-check-expiry logs-ssl logs-staging-ssl ssl-container-status ssl-container-restart ssl-container-restart-staging ssl-container-manual-renew ssl-container-manual-renew-staging ssl-switch-to-container ssl-switch-to-cron

help: ## Bu yardım mesajını göster
	@echo "Kullanılabilir komutlar:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development Commands
build: ## Docker imajlarını oluştur
	docker-compose build

up: ## Development servilerini çalıştır (PostgreSQL dahil)
	docker-compose up -d

down: ## Tüm servisleri durdur
	docker-compose down

# Production Commands  
build-prod: ## Production için Docker imajlarını oluştur
	docker-compose -f docker-compose.prod.yml build

up-prod: ## Production servilerini çalıştır (external DB default, --profile postgres for container DB)
	docker-compose -f docker-compose.prod.yml up -d

up-prod-postgres: ## Production servilerini PostgreSQL container ile çalıştır
	docker-compose -f docker-compose.prod.yml --profile postgres up -d

down-prod: ## Production servilerini durdur
	docker-compose -f docker-compose.prod.yml down

# Staging Commands
build-staging: ## Staging için Docker imajlarını oluştur
	docker-compose -f docker-compose.staging.yml build

up-staging: ## Staging servilerini çalıştır (container DB)
	docker-compose -f docker-compose.staging.yml up -d

down-staging: ## Staging servilerini durdur
	docker-compose -f docker-compose.staging.yml down

# Logging
logs: ## Development logları göster
	docker-compose logs -f

logs-prod: ## Production logları göster
	docker-compose -f docker-compose.prod.yml logs -f

logs-staging: ## Staging logları göster
	docker-compose -f docker-compose.staging.yml logs -f

logs-backend: ## Sadece backend loglarını göster
	docker-compose logs -f backend

logs-celery: ## Celery loglarını göster
	docker-compose logs -f celery celery-beat

# Database & Migrations
shell: ## Backend container'ında shell aç
	docker-compose exec backend /bin/bash

shell-db: ## PostgreSQL shell aç (sadece development)
	docker-compose exec postgres psql -U bp_user -d bp_db

migrate: ## Django migration'ları çalıştır
	docker-compose exec backend python manage.py migrate

migrate-prod: ## Production Django migration'ları çalıştır
	docker-compose -f docker-compose.prod.yml exec backend python manage.py migrate

migrate-staging: ## Staging Django migration'ları çalıştır
	docker-compose -f docker-compose.staging.yml exec backend python manage.py migrate

makemigrations: ## Yeni migration'lar oluştur
	docker-compose exec backend python manage.py makemigrations

createsuperuser: ## Django superuser oluştur
	docker-compose exec backend python manage.py createsuperuser

createsuperuser-prod: ## Production Django superuser oluştur
	docker-compose -f docker-compose.prod.yml exec backend python manage.py createsuperuser

createsuperuser-staging: ## Staging Django superuser oluştur
	docker-compose -f docker-compose.staging.yml exec backend python manage.py createsuperuser

collectstatic: ## Static dosyaları topla
	docker-compose exec backend python manage.py collectstatic --noinput

collectstatic-prod: ## Production static dosyaları topla
	docker-compose -f docker-compose.prod.yml exec backend python manage.py collectstatic --noinput

collectstatic-staging: ## Staging static dosyaları topla
	docker-compose -f docker-compose.staging.yml exec backend python manage.py collectstatic --noinput

# Utility Commands
restart: ## Development servisleri yeniden başlat
	make down && make up

restart-prod: ## Production servisleri yeniden başlat
	make down-prod && make up-prod

restart-staging: ## Staging servisleri yeniden başlat
	make down-staging && make up-staging

clean: ## Kullanılmayan Docker objelerini temizle
	docker system prune -f

dev: ## Development modunda çalıştır (reload ile)
	docker-compose exec backend python manage.py runserver 0.0.0.0:8000

test: ## Django testleri çalıştır
	docker-compose exec backend python manage.py test

# SSL Setup (Production)
ssl-init: ## Let's Encrypt SSL sertifikası al (ilk kurulum)
	@echo "🔒 SSL sertifikası alınıyor..."
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt -p 80:80 certbot/certbot \
		certonly --standalone -d ${DOMAIN} --email ${SSL_EMAIL} --agree-tos --non-interactive
	@echo "✅ SSL sertifikası başarıyla alındı!"

ssl-init-staging: ## Staging SSL sertifikası al (test sertifikası)
	@echo "🔒 Staging SSL sertifikası alınıyor (test sertifikası)..."
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt -p 8080:80 certbot/certbot \
		certonly --standalone --staging -d ${DOMAIN} --email ${SSL_EMAIL} --agree-tos --non-interactive
	@echo "✅ Staging SSL sertifikası başarıyla alındı! (Test sertifikası)"
	@echo "⚠️ Not: Bu test sertifikasıdır, browser'da güvenilmez görünür."

ssl-renew: ## SSL sertifikasını yenile
	@echo "🔄 SSL sertifikası yenileniyor..."
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt certbot/certbot \
		renew --quiet --no-self-upgrade
	@echo "✅ SSL sertifikası yenilendi!"
	@echo "🔄 Nginx yeniden başlatılıyor..."
	docker-compose -f docker-compose.prod.yml restart nginx
	@echo "✅ Nginx yeniden başlatıldı!"

ssl-status: ## SSL sertifikası durumunu kontrol et
	@echo "📋 SSL sertifikası durumu:"
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt certbot/certbot certificates

ssl-test-renewal: ## SSL yenileme testini çalıştır
	@echo "🧪 SSL yenileme testi yapılıyor..."
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt certbot/certbot renew --dry-run

ssl-setup-cron: ## Otomatik SSL yenileme cron job'u kur
	@echo "⏰ Cron job kuruluyor..."
	@echo "# SSL Otomatik Yenileme - Her ay 1'inde saat 03:00'da çalışır" > /tmp/ssl-cron
	@echo "0 3 1 * * cd $(PWD) && make ssl-renew >> /var/log/ssl-renewal.log 2>&1" >> /tmp/ssl-cron
	@sudo crontab -l 2>/dev/null | grep -v "SSL Otomatik Yenileme" > /tmp/current-cron || true
	@cat /tmp/current-cron /tmp/ssl-cron | sudo crontab -
	@rm /tmp/ssl-cron /tmp/current-cron
	@echo "✅ Cron job kuruldu! SSL sertifikası her ay otomatik yenilenecek."
	@echo "📋 Cron job'ları görmek için: sudo crontab -l"

ssl-enable-https: ## HTTPS yönlendirmesini aktifleştir (SSL kurulumu sonrası)
	@echo "🔒 HTTPS yönlendirmesi aktifleştiriliyor..."
	chmod +x scripts/ssl-enable-https.sh
	./scripts/ssl-enable-https.sh
	@echo "✅ HTTPS yönlendirmesi aktif! Nginx'i yeniden başlatın."

ssl-disable-https: ## HTTPS yönlendirmesini deaktif et (SSL kaldırma)
	@echo "🔓 HTTPS yönlendirmesi deaktif ediliyor..."
	@if [ -f nginx/default.conf.backup ]; then \
		cp nginx/default.conf.backup nginx/default.conf; \
		echo "✅ HTTPS yönlendirmesi deaktif edildi!"; \
	else \
		echo "❌ Backup dosyası bulunamadı!"; \
	fi

ssl-check-expiry: ## SSL sertifikası son kullanma tarihini kontrol et
	@echo "📅 SSL sertifikası bitiş tarihi:"
	docker run --rm -v $(PWD)/nginx/ssl:/etc/letsencrypt certbot/certbot \
		certificates --cert-name ${DOMAIN} | grep "Expiry Date"

# SSL Container Commands (Ana compose dosyalarında entegre)
logs-ssl: ## SSL container loglarını göster (production)
	@echo "📜 SSL container logları:"
	docker logs -f bp_certbot

logs-staging-ssl: ## SSL container loglarını göster (staging)
	@echo "📜 Staging SSL container logları:"
	docker logs -f bp_certbot_staging

ssl-container-status: ## SSL container durumunu kontrol et
	@echo "🔍 SSL container durumu:"
	docker ps | grep -E "(bp_certbot|certbot)" || echo "SSL container çalışmıyor"
	@echo "📊 Production SSL container health check:"
	docker inspect bp_certbot --format='{{.State.Health.Status}}' 2>/dev/null || echo "Production container bulunamadı"
	@echo "📊 Staging SSL container health check:"
	docker inspect bp_certbot_staging --format='{{.State.Health.Status}}' 2>/dev/null || echo "Staging container bulunamadı"

ssl-container-restart: ## SSL container'ı yeniden başlat (production)
	@echo "🔄 Production SSL container yeniden başlatılıyor..."
	docker restart bp_certbot
	@echo "✅ Production SSL container yeniden başlatıldı!"

ssl-container-restart-staging: ## SSL container'ı yeniden başlat (staging)
	@echo "🔄 Staging SSL container yeniden başlatılıyor..."
	docker restart bp_certbot_staging
	@echo "✅ Staging SSL container yeniden başlatıldı!"

ssl-container-manual-renew: ## SSL container'da manuel yenileme (production)
	@echo "🔄 Production SSL container'da manuel yenileme çalıştırılıyor..."
	docker exec bp_certbot certbot renew --force-renewal
	docker exec bp_nginx nginx -s reload
	@echo "✅ Production manuel yenileme tamamlandı!"

ssl-container-manual-renew-staging: ## SSL container'da manuel yenileme (staging)
	@echo "🔄 Staging SSL container'da manuel yenileme çalıştırılıyor..."
	docker exec bp_certbot_staging certbot renew --force-renewal
	docker exec bp_nginx_staging nginx -s reload
	@echo "✅ Staging manuel yenileme tamamlandı!"

# SSL Hibrit Yönetim
ssl-switch-to-container: ## Cron job'dan container'a geçiş
	@echo "🔄 Cron job'dan container yaklaşımına geçiliyor..."
	@echo "1. Mevcut cron job kaldırılıyor..."
	@sudo crontab -l 2>/dev/null | grep -v "SSL Otomatik Yenileme" | sudo crontab - || true
	@echo "2. Production servisleri durduruluyor..."
	make down-prod
	@echo "3. SSL container ile başlatılıyor..."
	make up-ssl
	@echo "✅ Container yaklaşımına geçiş tamamlandı!"
	@echo "📋 SSL container logları: make logs-ssl"

ssl-switch-to-cron: ## Container'dan cron job'a geçiş
	@echo "🔄 Container'dan cron job yaklaşımına geçiliyor..."
	@echo "1. SSL container durduruluyor..."
	make down-ssl
	@echo "2. Normal production başlatılıyor..."
	make up-prod
	@echo "3. Cron job kuruluyor..."
	make ssl-setup-cron
	@echo "✅ Cron job yaklaşımına geçiş tamamlandı!"
	@echo "📋 Cron job durumu: sudo crontab -l | grep SSL"