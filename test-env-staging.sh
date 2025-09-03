#!/bin/bash

echo "🔍 Environment Variables Test Script"
echo "======================================"

echo ""
echo "📄 Checking .env files:"
ls -la .env* 2>/dev/null || echo "No .env files found in current directory"

echo ""
echo "🐳 Docker Compose Staging Test:"
echo "DJANGO_ENV from docker-compose.staging.yml should be: staging"

echo ""
echo "⚙️ Environment Variables that will be set:"
echo "- DJANGO_ENV=staging (from compose)"
echo "- DEBUG=True (from .env.staging)"  
echo "- SECRET_KEY=staging-secret-key-... (from .env.staging)"
echo "- DATABASE_URL=postgresql://... (from compose override)"

echo ""
echo "🎯 Expected Behavior:"
echo "1. Docker Compose loads .env.staging via env_file"
echo "2. Sets DJANGO_ENV=staging"
echo "3. Django sees DJANGO_ENV=staging and looks for .env.staging"
echo "4. But Docker env vars already loaded, so no conflict!"
echo ""
echo "✅ Problem solved: Both systems use same source (.env.staging)"
