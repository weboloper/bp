#!/bin/bash
# Automated Restore Test Script
# Otomatik olarak backup'tan restore test yapar (aylık)
# Test database kullanır, production'a dokunmaz
# Usage: ./test_restore.sh

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

CONTAINER_NAME="${POSTGRES_CONTAINER:-bp_postgres}"
DB_USER="${POSTGRES_USER:-bp_user}"
BACKUP_DIR="${BACKUP_DIR:-/opt/backups/postgres}"

# Test database
TEST_DB_NAME="bp_restore_test"

# Notification
NOTIFY_EMAIL="${BACKUP_NOTIFY_EMAIL:-}"

# ============================================================================
# FUNCTIONS
# ============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log "❌ ERROR: $1"
    exit 1
}

send_notification() {
    local status=$1
    local message=$2
    
    if [ -n "$NOTIFY_EMAIL" ]; then
        echo "$message" | mail -s "Restore Test $status" $NOTIFY_EMAIL 2>/dev/null || true
    fi
}

cleanup_test_db() {
    log "🧹 Cleaning up test database..."
    docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d postgres -c \
        "DROP DATABASE IF EXISTS $TEST_DB_NAME;" >/dev/null 2>&1 || true
}

# ============================================================================
# PRE-CHECKS
# ============================================================================

log "🧪 Starting automated restore test..."
log "⚠️  This test uses a separate test database"
log "   Production database will NOT be affected"
log ""

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    error "Container '$CONTAINER_NAME' is not running!"
fi

# Find latest backup
LATEST_BACKUP=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f 2>/dev/null | sort -r | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    error "No backups found in $BACKUP_DIR"
fi

log "Latest backup: $(basename "$LATEST_BACKUP")"
log "Backup size: $(du -h "$LATEST_BACKUP" | cut -f1)"
log "Backup date: $(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$LATEST_BACKUP" 2>/dev/null || stat -c "%y" "$LATEST_BACKUP" | cut -d'.' -f1)"
log ""

# ============================================================================
# CLEANUP OLD TEST DB
# ============================================================================

cleanup_test_db

# ============================================================================
# CREATE TEST DATABASE
# ============================================================================

log "🔄 Creating test database..."

if docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d postgres -c \
    "CREATE DATABASE $TEST_DB_NAME OWNER $DB_USER;" >/dev/null 2>&1; then
    log "✅ Test database created: $TEST_DB_NAME"
else
    error "Failed to create test database"
fi

# ============================================================================
# RESTORE TO TEST DATABASE
# ============================================================================

log "🔄 Restoring backup to test database..."

START_TIME=$(date +%s)

# Restore backup
if gunzip < "$LATEST_BACKUP" | docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$TEST_DB_NAME" >/dev/null 2>&1; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    log "✅ Restore completed in ${DURATION}s"
else
    cleanup_test_db
    error "Restore failed!"
fi

# ============================================================================
# VERIFICATION
# ============================================================================

log "🔍 Verifying restored data..."

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Check if database exists
log "Test 1: Database existence..."
if docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -l | grep -q "$TEST_DB_NAME"; then
    log "  ✅ PASSED"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log "  ❌ FAILED"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: Check table count
log "Test 2: Table count..."
TABLE_COUNT=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$TEST_DB_NAME" -t -c \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')

if [ -n "$TABLE_COUNT" ] && [ "$TABLE_COUNT" -gt 0 ]; then
    log "  ✅ PASSED (Found $TABLE_COUNT tables)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log "  ❌ FAILED (No tables found)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 3: Check Django migrations table
log "Test 3: Django migrations table..."
MIGRATIONS_COUNT=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$TEST_DB_NAME" -t -c \
    "SELECT COUNT(*) FROM django_migrations;" 2>/dev/null | tr -d ' ') || MIGRATIONS_COUNT=0

if [ "$MIGRATIONS_COUNT" -gt 0 ]; then
    log "  ✅ PASSED (Found $MIGRATIONS_COUNT migrations)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log "  ⚠️  WARNING (No migrations found - might be an issue)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 4: Check auth_user table (common Django table)
log "Test 4: User table..."
USER_COUNT=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$TEST_DB_NAME" -t -c \
    "SELECT COUNT(*) FROM auth_user;" 2>/dev/null | tr -d ' ') || USER_COUNT=-1

if [ "$USER_COUNT" -ge 0 ]; then
    log "  ✅ PASSED (Found $USER_COUNT users)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log "  ⚠️  WARNING (Could not query user table)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 5: Sample data query
log "Test 5: Sample data accessibility..."
SAMPLE_QUERY=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$TEST_DB_NAME" -t -c \
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 5;" 2>/dev/null)

if [ -n "$SAMPLE_QUERY" ]; then
    log "  ✅ PASSED (Can query tables)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log "  ❌ FAILED (Cannot query tables)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# CLEANUP
# ============================================================================

cleanup_test_db

# ============================================================================
# RESULTS
# ============================================================================

log ""
log "═══════════════════════════════════════════════════════"
log "📊 RESTORE TEST RESULTS"
log "═══════════════════════════════════════════════════════"
log "Backup tested: $(basename "$LATEST_BACKUP")"
log "Restore duration: ${DURATION}s"
log "Tests passed: $TESTS_PASSED"
log "Tests failed: $TESTS_FAILED"
log "═══════════════════════════════════════════════════════"

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
SUCCESS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))

if [ $TESTS_FAILED -eq 0 ]; then
    log "✅ ALL TESTS PASSED (100%)"
    log ""
    log "💡 Restore from backup is working correctly!"
    log "   Your backups are reliable and can be used for recovery."
    
    if [ -n "$NOTIFY_EMAIL" ]; then
        send_notification "SUCCESS" "Restore test completed successfully!

Backup: $(basename "$LATEST_BACKUP")
Restore duration: ${DURATION}s
Tests: $TESTS_PASSED/$TOTAL_TESTS passed (100%)

Your backups are working correctly and can be trusted for recovery."
    fi
    
    exit 0
else
    log "❌ SOME TESTS FAILED (${SUCCESS_RATE}%)"
    log ""
    log "⚠️  WARNING: There may be issues with your backup/restore process!"
    log "   Review the test results and investigate failures."
    
    if [ -n "$NOTIFY_EMAIL" ]; then
        send_notification "FAILED" "⚠️ Restore test found issues!

Backup: $(basename "$LATEST_BACKUP")
Tests: $TESTS_PASSED/$TOTAL_TESTS passed (${SUCCESS_RATE}%)
Failed tests: $TESTS_FAILED

Please review backup logs and test results."
    fi
    
    exit 1
fi
