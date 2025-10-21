#!/bin/bash
# PostgreSQL Restore Script
# Backup dosyasından database restore eder
# Usage: ./restore_db.sh <backup_file.sql.gz>

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

CONTAINER_NAME="${POSTGRES_CONTAINER:-bp_postgres}"
DB_USER="${POSTGRES_USER:-bp_user}"
DB_NAME="${POSTGRES_DB:-bp_db}"
BACKUP_FILE="$1"

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

# ============================================================================
# PRE-CHECKS
# ============================================================================

# Check if backup file is provided
if [ -z "$BACKUP_FILE" ]; then
    log "❌ Usage: $0 <backup_file.sql.gz>"
    log ""
    log "Available backups:"
    find /opt/backups/postgres -name "backup_*.sql.gz" -type f 2>/dev/null | sort -r | head -10 || \
    echo "  No backups found in /opt/backups/postgres"
    exit 1
fi

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    error "Backup file not found: $BACKUP_FILE"
fi

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    error "Container '$CONTAINER_NAME' is not running!"
fi

# ============================================================================
# CONFIRMATION
# ============================================================================

log "⚠️  WARNING: This will REPLACE the current database!"
log ""
log "Database: $DB_NAME"
log "Container: $CONTAINER_NAME"
log "Backup file: $BACKUP_FILE"
log "Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"
log "Backup date: $(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$BACKUP_FILE" 2>/dev/null || stat -c "%y" "$BACKUP_FILE" | cut -d'.' -f1)"
log ""

# Ask for confirmation
read -p "Are you sure you want to restore? Type 'yes' to confirm: " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    log "❌ Restore cancelled"
    exit 0
fi

log ""
log "🔄 Starting database restore..."

# ============================================================================
# BACKUP CURRENT DATABASE (Safety)
# ============================================================================

log "📦 Creating safety backup of current database..."
SAFETY_BACKUP="/tmp/safety_backup_$(date +%Y%m%d_%H%M%S).sql.gz"

if docker exec "$CONTAINER_NAME" pg_dump -U "$DB_USER" -d "$DB_NAME" 2>/dev/null | gzip > "$SAFETY_BACKUP"; then
    SAFETY_SIZE=$(du -h "$SAFETY_BACKUP" | cut -f1)
    log "✅ Safety backup created: $SAFETY_BACKUP ($SAFETY_SIZE)"
    log "   (You can restore this if something goes wrong)"
else
    log "⚠️  WARNING: Could not create safety backup (continuing anyway)"
fi

# ============================================================================
# RESTORE DATABASE
# ============================================================================

log "🔄 Closing active connections..."

# Terminate all connections to the database
docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d postgres -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();" \
    >/dev/null 2>&1 || true

log "🔄 Dropping and recreating database..."

# Drop and recreate database
docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;" || \
    error "Failed to drop database"

docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || \
    error "Failed to create database"

log "🔄 Restoring backup..."

START_TIME=$(date +%s)

# Restore backup
if [[ $BACKUP_FILE == *.gz ]]; then
    # Compressed backup
    if gunzip < "$BACKUP_FILE" | docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
        RESTORE_SUCCESS=true
    else
        RESTORE_SUCCESS=false
    fi
else
    # Uncompressed backup
    if cat "$BACKUP_FILE" | docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
        RESTORE_SUCCESS=true
    else
        RESTORE_SUCCESS=false
    fi
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ============================================================================
# VERIFICATION
# ============================================================================

if [ "$RESTORE_SUCCESS" = true ]; then
    log "✅ Restore completed in ${DURATION}s"
    log ""
    log "🔍 Verifying restored database..."
    
    # Check if database has tables
    TABLE_COUNT=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')
    
    if [ -n "$TABLE_COUNT" ] && [ "$TABLE_COUNT" -gt 0 ]; then
        log "✅ Database verification successful"
        log "   Tables found: $TABLE_COUNT"
        log ""
        log "📋 Sample tables:"
        docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -c "\dt" 2>/dev/null | head -15
        
        # Clean up safety backup
        if [ -f "$SAFETY_BACKUP" ]; then
            log ""
            log "🗑️  Safety backup can be removed: $SAFETY_BACKUP"
            read -p "Delete safety backup? (yes/no): " DELETE_SAFETY
            if [ "$DELETE_SAFETY" = "yes" ]; then
                rm -f "$SAFETY_BACKUP"
                log "✅ Safety backup deleted"
            else
                log "💾 Safety backup kept at: $SAFETY_BACKUP"
            fi
        fi
    else
        log "⚠️  WARNING: No tables found in restored database!"
        log "   This might indicate a problem with the backup file"
    fi
    
    log ""
    log "✅ Restore process completed successfully!"
    
else
    error "Restore failed! 
Your original database is still intact (via safety backup).
Safety backup location: $SAFETY_BACKUP

To restore the safety backup:
  $0 $SAFETY_BACKUP"
fi

exit 0
