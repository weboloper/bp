.PHONY: help build up down logs shell migrate createsuperuser collectstatic

help: ## Bu yardım mesajını göster
	@echo "Kullanılabilir komutlar:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Docker imajlarını oluştur
	docker-compose build

up: ## Tüm servisleri çalıştır
	docker-compose up -d

up-frontend: ## Frontend ile birlikte tüm servisleri çalıştır  
	docker-compose -f docker-compose.yml -f docker-compose.frontend.yml up -d

down: ## Tüm servisleri durdur
	docker-compose down

logs: ## Logları göster
	docker-compose logs -f

logs-backend: ## Sadece backend loglarını göster
	docker-compose logs -f backend

logs-celery: ## Celery loglarını göster
	docker-compose logs -f celery celery-beat

shell: ## Backend container'ında shell aç
	docker-compose exec backend /bin/bash

shell-db: ## PostgreSQL shell aç
	docker-compose exec postgres psql -U bp_user -d bp_db

migrate: ## Django migration'ları çalıştır
	docker-compose exec backend python manage.py migrate

makemigrations: ## Yeni migration'lar oluştur
	docker-compose exec backend python manage.py makemigrations

createsuperuser: ## Django superuser oluştur
	docker-compose exec backend python manage.py createsuperuser

collectstatic: ## Static dosyaları topla
	docker-compose exec backend python manage.py collectstatic --noinput

restart: ## Servisleri yeniden başlat
	make down && make up

clean: ## Kullanılmayan Docker objelerini temizle
	docker system prune -f

dev: ## Development modunda çalıştır (reload ile)
	docker-compose exec backend python manage.py runserver 0.0.0.0:8000

test: ## Django testleri çalıştır
	docker-compose exec backend python manage.py test
