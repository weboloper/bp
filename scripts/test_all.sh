#!/bin/bash
# Windows Test Script
# Git Bash'te çalıştır: bash scripts/test_all.sh

echo "🧪 Starting Backup Scripts Test Suite..."
echo ""

# Set environment variables for Windows
export BACKUP_DIR=/d/opt/backups/postgres
export MEDIA_BACKUP_DIR=/d/opt/backups/media
export MEDIA_DIR=./backend/media
export POSTGRES_CONTAINER=bp_postgres
export POSTGRES_USER=bp_user
export POSTGRES_DB=bp_db

echo "✅ Environment variables set"
echo ""

# Test 1: PostgreSQL Backup
echo "═══════════════════════════════════════"
echo "Test 1: PostgreSQL Backup"
echo "═══════════════════════════════════════"
if bash scripts/backup_db.sh; then
    echo "✅ PostgreSQL backup PASSED"
else
    echo "❌ PostgreSQL backup FAILED"
    exit 1
fi
echo ""

# Test 2: Media Backup
echo "═══════════════════════════════════════"
echo "Test 2: Media Backup"
echo "═══════════════════════════════════════"
if bash scripts/backup_media.sh; then
    echo "✅ Media backup PASSED"
else
    echo "❌ Media backup FAILED"
    exit 1
fi
echo ""

# Test 3: Health Check
echo "═══════════════════════════════════════"
echo "Test 3: Health Check"
echo "═══════════════════════════════════════"
if bash scripts/check_backup.sh; then
    echo "✅ Health check PASSED"
else
    echo "❌ Health check FAILED"
    exit 1
fi
echo ""

# Test 4: Automated Restore Test
echo "═══════════════════════════════════════"
echo "Test 4: Automated Restore Test"
echo "═══════════════════════════════════════"
if bash scripts/test_restore.sh; then
    echo "✅ Restore test PASSED"
else
    echo "❌ Restore test FAILED"
    exit 1
fi
echo ""

# Summary
echo "═══════════════════════════════════════"
echo "🎉 ALL TESTS PASSED!"
echo "═══════════════════════════════════════"
echo ""
echo "📁 Backup locations:"
echo "  PostgreSQL: $BACKUP_DIR"
echo "  Media: $MEDIA_BACKUP_DIR"
echo ""
echo "Next steps:"
echo "  1. Review backup files"
echo "  2. Test manual restore (optional)"
echo "  3. Setup cron jobs on VPS"
echo ""
