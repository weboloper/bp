FROM nginx:alpine

# SSL ve Certbot için gerekli dizinleri oluştur
RUN mkdir -p /etc/nginx/ssl \
    && mkdir -p /var/www/certbot \
    && mkdir -p /etc/letsencrypt

# Nginx konfigürasyonlarını kopyala
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/templates/default.conf.template

# Development konfigürasyonunu ayrı bir yere koyalım
COPY default.dev.conf /etc/nginx/dev-config/default.dev.conf

# SSL dizinleri için doğru izinleri ayarla
RUN chown -R nginx:nginx /var/www/certbot \
    && chown -R nginx:nginx /etc/nginx/ssl \
    && chmod -R 755 /var/www/certbot \
    && mkdir -p /etc/nginx/dev-config

# Templates dizinini temizle (otomatik envsubst'u engelle)
RUN rm -rf /etc/nginx/templates/*

# Startup script oluştur
RUN echo '#!/bin/sh' > /docker-entrypoint.d/40-setup-config.sh && \
    echo 'if [ "$DOMAIN" = "localhost" ] || [ -z "$DOMAIN" ]; then' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo '  echo "Development mode: Using HTTP-only configuration"' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo '  cp /etc/nginx/dev-config/default.dev.conf /etc/nginx/conf.d/default.conf' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo 'else' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo '  echo "Production mode: Using HTTPS configuration"' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo '  envsubst '"'"'$DOMAIN'"'"' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf' >> /docker-entrypoint.d/40-setup-config.sh && \
    echo 'fi' >> /docker-entrypoint.d/40-setup-config.sh && \
    chmod +x /docker-entrypoint.d/40-setup-config.sh

# Port aç
EXPOSE 80 443

# Nginx'i başlat
CMD ["nginx", "-g", "daemon off;"]