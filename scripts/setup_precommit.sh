#!/bin/bash
# 🔧 Pre-commit Setup Script
# Usage: ./scripts/setup_precommit.sh

set -e

echo "🔧 Setting up pre-commit hooks for BP Boilerplate..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if containers are running
if ! docker compose ps | grep -q "Up"; then
    echo "📦 Starting development containers..."
    make up
    sleep 10
fi

echo "📦 Installing pre-commit dependencies..."
docker compose exec backend pip install pre-commit black isort flake8 bandit django-upgrade

echo "🔧 Installing pre-commit hooks..."
docker compose exec backend pre-commit install

echo "🧪 Running pre-commit on all files (initial setup)..."
docker compose exec backend pre-commit run --all-files || echo "⚠️ Some files were reformatted - this is normal on first run"

echo ""
echo "✅ Pre-commit setup completed!"
echo ""
echo "📋 Usage:"
echo "   make format          # Format code manually"
echo "   make lint            # Run linting checks"
echo "   make code-check      # Run all quality checks"
echo "   make precommit-run   # Run pre-commit on all files"
echo ""
echo "💡 From now on, commits will be automatically checked!"
echo "   If a commit fails, fix the issues and commit again."
echo ""
echo "🎯 Example workflow:"
echo "   1. Write your code"
echo "   2. git add ."
echo "   3. git commit -m 'your message'"
echo "   4. Pre-commit automatically runs and may fix/flag issues"
echo "   5. If issues found, fix them and commit again"
echo ""
