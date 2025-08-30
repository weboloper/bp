FROM python:3.11-slim

# Sistem paketlerini güncelle
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    gettext \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizinini oluştur
WORKDIR /app

# Python paketlerini kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje dosyalarını kopyala
COPY . .

# Static dosyalar için dizin oluştur
RUN mkdir -p /app/static /app/media

# Port aç
EXPOSE 8000

# Varsayılan komut
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]
