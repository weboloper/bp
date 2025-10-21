#!/bin/bash
# PostgreSQL Backup Script
# Günlük PostgreSQL backup alır, eski backupları temizler
# Usage: ./backup_db.sh

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

# Container ve database bilgileri
CONTAINER_NAME="${POSTGRES_CONTAINER:-bp_postgres}"
DB_USER="${POSTGRES_USER:-bp_user}"
DB_NAME="${POSTGRES_DB:-bp_db}"

# Backup dizini ve retention
BACKUP_DIR="${BACKUP_DIR:-/opt/backups/postgres}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"

# Offsite backup (AWS S3)
OFFSITE_ENABLED="${OFFSITE_BACKUP_ENABLED:-false}"
AWS_BUCKET="${AWS_S3_BACKUP_BUCKET:-}"
AWS_REGION="${AWS_REGION:-eu-central-1}"

# Notification (optional)
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
        echo "$message" | mail -s "Backup $status: PostgreSQL" $NOTIFY_EMAIL 2>/dev/null || true
    fi
}

# ============================================================================
# PRE-CHECKS
# ============================================================================

log "🔄 Starting PostgreSQL backup..."

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    error "Container '$CONTAINER_NAME' is not running!"
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# ============================================================================
# BACKUP
# ============================================================================

# Backup filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_${TIMESTAMP}.sql.gz"
LOG_FILE="$BACKUP_DIR/backup_${TIMESTAMP}.log"

log "Database: $DB_NAME"
log "Container: $CONTAINER_NAME"
log "Backup file: $BACKUP_FILE"

# Perform backup
START_TIME=$(date +%s)

if docker exec "$CONTAINER_NAME" pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$BACKUP_FILE" 2>"$LOG_FILE"; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    # Get backup size
    BACKUP_SIZE_BYTES=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE")
    BACKUP_SIZE_MB=$((BACKUP_SIZE_BYTES / 1024 / 1024))
    BACKUP_SIZE_HR=$(du -h "$BACKUP_FILE" | cut -f1)
    
    log "✅ Backup completed successfully!"
    log "Size: $BACKUP_SIZE_HR (${BACKUP_SIZE_MB}MB)"
    log "Duration: ${DURATION}s"
    
    # Verify backup integrity
    if gunzip -t "$BACKUP_FILE" 2>/dev/null; then
        log "✅ Backup integrity verified"
    else
        error "Backup file integrity check FAILED!"
    fi
    
    # Warning if backup is suspiciously small
    if [ $BACKUP_SIZE_MB -lt 1 ]; then
        log "⚠️  WARNING: Backup size is very small (${BACKUP_SIZE_MB}MB)"
    fi
    
else
    error "Backup failed! Check log: $LOG_FILE"
fi

# ============================================================================
# CLEANUP OLD BACKUPS
# ============================================================================

log "🧹 Cleaning old backups (older than $RETENTION_DAYS days)..."

# Count backups before cleanup
BEFORE_COUNT=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" 2>/dev/null | wc -l)

# Delete old backups
find "$BACKUP_DIR" -name "backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "backup_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

# Count backups after cleanup
AFTER_COUNT=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" 2>/dev/null | wc -l)
DELETED=$((BEFORE_COUNT - AFTER_COUNT))

log "Deleted $DELETED old backup(s)"
log "Remaining: $AFTER_COUNT backup(s)"

# Show total backup size
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
log "Total backup size: $TOTAL_SIZE"

# ============================================================================
# OFFSITE BACKUP (AWS S3)
# ============================================================================

if [ "$OFFSITE_ENABLED" = "true" ]; then
    log "☁️  Uploading to AWS S3..."
    
    if [ -z "$AWS_BUCKET" ]; then
        log "⚠️  WARNING: AWS_S3_BACKUP_BUCKET not configured, skipping offsite backup"
    else
        # Check if AWS CLI is available
        if command -v aws >/dev/null 2>&1; then
            S3_PATH="s3://$AWS_BUCKET/postgres/$(date +%Y)/$(date +%m)/"
            
            if aws s3 cp "$BACKUP_FILE" "$S3_PATH" --region "$AWS_REGION" 2>&1 | tee -a "$LOG_FILE"; then
                log "✅ Offsite backup completed: $S3_PATH"
            else
                log "❌ Offsite backup failed (continuing...)"
            fi
        else
            log "⚠️  WARNING: AWS CLI not installed, skipping offsite backup"
            log "Install: pip install awscli && aws configure"
        fi
    fi
else
    log "⏭️  Offsite backup disabled (OFFSITE_BACKUP_ENABLED=false)"
fi

# ============================================================================
# SUMMARY
# ============================================================================

log "📊 Backup Summary:"
log "  Latest backup: $(basename $BACKUP_FILE)"
log "  Size: $BACKUP_SIZE_HR"
log "  Duration: ${DURATION}s"
log "  Retention: $RETENTION_DAYS days"
log "  Total backups: $AFTER_COUNT"
log "  Offsite: $([ "$OFFSITE_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")"

log "✅ Backup process completed!"

# Send success notification
if [ -n "$NOTIFY_EMAIL" ]; then
    send_notification "SUCCESS" "PostgreSQL backup completed successfully
Database: $DB_NAME
Size: $BACKUP_SIZE_HR
Duration: ${DURATION}s
Backups: $AFTER_COUNT"
fi

exit 0
