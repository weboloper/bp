FROM caddy:2.7.6-alpine

# Caddy plugins eklemek için (gerekirse)
# RUN caddy add-package github.com/greenpau/caddy-security

# Caddyfile'ı kopyala
COPY Caddyfile /etc/caddy/Caddyfile

# Log dizini oluştur
RUN mkdir -p /var/log/caddy

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD caddy validate --config /etc/caddy/Caddyfile || exit 1

# Port expose
EXPOSE 80 443

# Caddy'yi başlat
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
