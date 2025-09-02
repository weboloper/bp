#!/bin/bash

# SSL HTTPS Redirect Aktifleştirme Script'i
# Bu script nginx konfigürasyonunda HTTPS yönlendirmesini aktif hale getirir

set -e

CONFIG_FILE="nginx/default.conf"
BACKUP_FILE="nginx/default.conf.backup"

echo "🔒 SSL HTTPS yönlendirmesi aktifleştiriliyor..."

# Backup oluştur
if [ ! -f "$BACKUP_FILE" ]; then
    cp "$CONFIG_FILE" "$BACKUP_FILE"
    echo "✅ Backup oluşturuldu: $BACKUP_FILE"
fi

# HTTP'yi HTTPS'e yönlendirmeyi aktifleştir
sed -i 's/# return 301 https:\/\/$host$request_uri;/return 301 https:\/\/$host$request_uri;/' "$CONFIG_FILE"
sed -i 's/# location \/ {/location \/ {/' "$CONFIG_FILE"
sed -i 's/# }/}/' "$CONFIG_FILE"

# Development proxy'yi deaktif et
sed -i 's/location \/ {/# location \/ {/' "$CONFIG_FILE"
sed -i '/proxy_pass http:\/\/backend;/,/}/ s/^/# /' "$CONFIG_FILE"

echo "✅ HTTPS yönlendirmesi aktifleştirildi!"
echo "🔄 Nginx'i yeniden başlatmayı unutmayın: make restart-prod"

# Değişiklikleri göster
echo "📝 Yapılan değişiklikler:"
diff "$BACKUP_FILE" "$CONFIG_FILE" || true