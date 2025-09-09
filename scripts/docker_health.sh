#!/bin/bash
# 🐳 Docker Container Health Check
# Usage: ./docker_health.sh [environment]

set -e

ENV=${1:-staging}

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$ENV" = "production" ]; then
    COMPOSE_FILE="docker-compose.prod.yml"
elif [ "$ENV" = "staging" ]; then
    COMPOSE_FILE="docker-compose.staging.yml"
else
    COMPOSE_FILE="docker-compose.yml"
fi

echo -e "${BLUE}🐳 Docker Container Health Check - $ENV${NC}"
echo "================================================="

# 1. Container Status
echo -e "\n📦 Container Status:"
docker-compose -f $COMPOSE_FILE ps

echo -e "\n💾 Container Resources:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

echo -e "\n🔍 Service Health:"

# Check each critical service
services=("backend" "postgres" "redis" "caddy")

if [ "$ENV" != "development" ]; then
    services+=("celery" "celery-beat")
fi

for service in "${services[@]}"; do
    echo -n "   $service: "
    
    if [ "$ENV" = "staging" ]; then
        container_name="bp_${service}_staging"
        if [ "$service" = "postgres" ]; then
            container_name="bp_postgres_staging"
        elif [ "$service" = "celery" ]; then
            container_name="bp_celery_staging"
        elif [ "$service" = "celery-beat" ]; then
            container_name="bp_celery_beat_staging"
        elif [ "$service" = "caddy" ]; then
            container_name="bp_caddy_staging"
        elif [ "$service" = "backend" ]; then
            container_name="bp_backend_staging"
        fi
    elif [ "$ENV" = "production" ]; then
        if [ "$service" = "caddy" ]; then
            container_name="bp_caddy"
        elif [ "$service" = "backend" ]; then
            container_name="bp_backend"
        elif [ "$service" = "postgres" ]; then
            container_name="bp_postgres_prod"
        else
            container_name="bp_${service}"
        fi
    else
        container_name="bp_${service}"
    fi
    
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        echo -e "${GREEN}✅ RUNNING${NC}"
    else
        echo -e "${RED}❌ NOT RUNNING${NC}"
    fi
done

echo -e "\n📊 Container Logs (last 5 lines):"
echo "================================="

for service in "${services[@]}"; do
    echo -e "\n${BLUE}🔗 $service logs:${NC}"
    docker-compose -f $COMPOSE_FILE logs --tail=5 $service 2>/dev/null || echo "  No logs available"
done

echo -e "\n🎯 Quick Commands:"
echo "   View logs:     docker-compose -f $COMPOSE_FILE logs [service]"
echo "   Restart:       docker-compose -f $COMPOSE_FILE restart [service]"
echo "   Shell access:  docker-compose -f $COMPOSE_FILE exec [service] /bin/bash"
echo "   Status:        docker-compose -f $COMPOSE_FILE ps"

echo -e "\n✅ Docker health check completed!"
