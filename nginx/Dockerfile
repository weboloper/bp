FROM nginx:alpine

# SSL sertifikaları için dizin oluştur
RUN mkdir -p /etc/nginx/ssl

# Nginx konfigürasyonunu kopyala
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

# Port aç
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
