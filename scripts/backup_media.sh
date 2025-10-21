#!/bin/bash
# Media Files Backup Script
# Haftalık media files backup alır (avatars, uploads, documents)
# Usage: ./backup_media.sh

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

# Media dizini ve backup dizini
MEDIA_DIR="${MEDIA_DIR:-./backend/media}"
BACKUP_DIR="${MEDIA_BACKUP_DIR:-/opt/backups/media}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"  # Media için daha uzun retention

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
        echo "$message" | mail -s "Backup $status: Media Files" $NOTIFY_EMAIL 2>/dev/null || true
    fi
}

# ============================================================================
# PRE-CHECKS
# ============================================================================

log "🔄 Starting media files backup..."

# Check if media directory exists
if [ ! -d "$MEDIA_DIR" ]; then
    error "Media directory not found: $MEDIA_DIR"
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Check if media directory is empty
FILE_COUNT=$(find "$MEDIA_DIR" -type f 2>/dev/null | wc -l)
if [ "$FILE_COUNT" -eq 0 ]; then
    log "⚠️  WARNING: Media directory is empty, skipping backup"
    exit 0
fi

# ============================================================================
# BACKUP
# ============================================================================

# Backup filename with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/media_backup_${TIMESTAMP}.tar.gz"
LOG_FILE="$BACKUP_DIR/media_backup_${TIMESTAMP}.log"

log "Media directory: $MEDIA_DIR"
log "Backup file: $BACKUP_FILE"
log "Files to backup: $FILE_COUNT"

# Perform backup with tar
START_TIME=$(date +%s)

if tar -czf "$BACKUP_FILE" -C "$(dirname "$MEDIA_DIR")" "$(basename "$MEDIA_DIR")" 2>"$LOG_FILE"; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    # Get backup size
    BACKUP_SIZE_BYTES=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE")
    BACKUP_SIZE_MB=$((BACKUP_SIZE_BYTES / 1024 / 1024))
    BACKUP_SIZE_HR=$(du -h "$BACKUP_FILE" | cut -f1)
    
    log "✅ Media backup completed successfully!"
    log "Size: $BACKUP_SIZE_HR (${BACKUP_SIZE_MB}MB)"
    log "Duration: ${DURATION}s"
    
    # Verify backup integrity
    if tar -tzf "$BACKUP_FILE" >/dev/null 2>&1; then
        log "✅ Backup integrity verified"
    else
        error "Backup file integrity check FAILED!"
    fi
    
else
    error "Media backup failed! Check log: $LOG_FILE"
fi

# ============================================================================
# CLEANUP OLD BACKUPS
# ============================================================================

log "🧹 Cleaning old backups (older than $RETENTION_DAYS days)..."

# Count backups before cleanup
BEFORE_COUNT=$(find "$BACKUP_DIR" -name "media_backup_*.tar.gz" 2>/dev/null | wc -l)

# Delete old backups
find "$BACKUP_DIR" -name "media_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "media_backup_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

# Count backups after cleanup
AFTER_COUNT=$(find "$BACKUP_DIR" -name "media_backup_*.tar.gz" 2>/dev/null | wc -l)
DELETED=$((BEFORE_COUNT - AFTER_COUNT))

log "Deleted $DELETED old backup(s)"
log "Remaining: $AFTER_COUNT backup(s)"

# Show total backup size
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
log "Total media backup size: $TOTAL_SIZE"

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
            S3_PATH="s3://$AWS_BUCKET/media/$(date +%Y)/$(date +%m)/"
            
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

log "📊 Media Backup Summary:"
log "  Latest backup: $(basename $BACKUP_FILE)"
log "  Files backed up: $FILE_COUNT"
log "  Size: $BACKUP_SIZE_HR"
log "  Duration: ${DURATION}s"
log "  Retention: $RETENTION_DAYS days"
log "  Total backups: $AFTER_COUNT"
log "  Offsite: $([ "$OFFSITE_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")"

log "✅ Media backup process completed!"

# Send success notification
if [ -n "$NOTIFY_EMAIL" ]; then
    send_notification "SUCCESS" "Media files backup completed successfully
Files: $FILE_COUNT
Size: $BACKUP_SIZE_HR
Duration: ${DURATION}s
Backups: $AFTER_COUNT"
fi

exit 0
