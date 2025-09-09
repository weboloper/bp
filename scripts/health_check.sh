#!/bin/bash
# 🩺 BP Health Check Script
# Usage: ./health_check.sh [environment]

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default environment
ENV=${1:-staging}

if [ "$ENV" = "production" ]; then
    BASE_URL="https://yourdomain.com"
    FLOWER_PORT="5555"
elif [ "$ENV" = "staging" ]; then
    BASE_URL="https://staging.yourdomain.com"
    FLOWER_PORT="5556"
else
    BASE_URL="http://localhost"
    FLOWER_PORT="5555"
fi

echo "🩺 BP Health Check - $ENV Environment"
echo "==============================================="

# 1. Main Application Health
echo -n "🌐 Django Application: "
if curl -s "$BASE_URL/health/" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ HEALTHY${NC}"
else
    echo -e "${RED}❌ UNHEALTHY${NC}"
    exit 1
fi

# 2. Database Connection
echo -n "🗄️  Database Connection: "
DB_STATUS=$(curl -s "$BASE_URL/health/" | jq -r '.status')
if [ "$DB_STATUS" = "healthy" ]; then
    echo -e "${GREEN}✅ CONNECTED${NC}"
else
    echo -e "${RED}❌ DISCONNECTED${NC}"
fi

# 3. Static Files
echo -n "📁 Static Files: "
if curl -s -I "$BASE_URL/static/admin/css/base.css" | head -n 1 | grep -q "200 OK"; then
    echo -e "${GREEN}✅ SERVING${NC}"
else
    echo -e "${RED}❌ NOT SERVING${NC}"
fi

# 4. Redis/Celery (if not development)
if [ "$ENV" != "development" ]; then
    echo -n "🔄 Celery Workers: "
    # SSH tunnel gerekli for flower check
    echo -e "${YELLOW}⚠️  SSH TUNNEL REQUIRED${NC}"
fi

# 5. SSL Certificate (if HTTPS)
if [[ "$BASE_URL" == https* ]]; then
    echo -n "🔐 SSL Certificate: "
    SSL_EXPIRY=$(echo | openssl s_client -servername $(echo $BASE_URL | cut -d'/' -f3) -connect $(echo $BASE_URL | cut -d'/' -f3):443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ VALID${NC} (Expires: $SSL_EXPIRY)"
    else
        echo -e "${RED}❌ INVALID${NC}"
    fi
fi

# 6. Response Time
echo -n "⚡ Response Time: "
RESPONSE_TIME=$(curl -s -w "%{time_total}" "$BASE_URL/health/" -o /dev/null)
if (( $(echo "$RESPONSE_TIME < 2.0" | bc -l) )); then
    echo -e "${GREEN}✅ FAST${NC} (${RESPONSE_TIME}s)"
elif (( $(echo "$RESPONSE_TIME < 5.0" | bc -l) )); then
    echo -e "${YELLOW}⚠️  SLOW${NC} (${RESPONSE_TIME}s)"
else
    echo -e "${RED}❌ TOO SLOW${NC} (${RESPONSE_TIME}s)"
fi

echo ""
echo "📊 Detailed Health Info:"
curl -s "$BASE_URL/health/" | jq .

echo ""
echo "🎯 Quick Commands:"
echo "   Health:   curl $BASE_URL/health/"
echo "   Home:     curl $BASE_URL/"
echo "   Admin:    $BASE_URL/admin/"

if [ "$ENV" != "development" ]; then
    echo "   Flower:   ssh -L $FLOWER_PORT:localhost:$FLOWER_PORT root@YOUR_VPS_IP"
fi

echo ""
echo "✅ Health check completed!"
