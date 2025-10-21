#!/bin/bash
# Backup Health Check Script
# Backup'ların sağlığını kontrol eder (yaş, boyut, bütünlük)
# Usage: ./check_backup.sh

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

BACKUP_DIR="${BACKUP_DIR:-/opt/backups/postgres}"
MEDIA_BACKUP_DIR="${MEDIA_BACKUP_DIR:-/opt/backups/media}"
MAX_AGE_HOURS="${BACKUP_MAX_AGE_HOURS:-26}"  # 26 saat (günlük + 2 saat tolerans)
MIN_SIZE_MB="${BACKUP_MIN_SIZE_MB:-1}"        # Minimum backup boyutu (MB)

# Notification
NOTIFY_EMAIL="${BACKUP_NOTIFY_EMAIL:-}"

# ============================================================================
# FUNCTIONS
# ============================================================================

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

warn() {
    log "⚠️  WARNING: $1"
}

error() {
    log "❌ ERROR: $1"
}

send_alert() {
    local subject=$1
    local message=$2
    
    if [ -n "$NOTIFY_EMAIL" ]; then
        echo "$message" | mail -s "$subject" $NOTIFY_EMAIL 2>/dev/null || true
    fi
}

check_file_age() {
    local file=$1
    local max_age=$2
    
    if [ ! -f "$file" ]; then
        return 1
    fi
    
    # File age in hours
    local file_time=$(stat -f %m "$file" 2>/dev/null || stat -c %Y "$file")
    local current_time=$(date +%s)
    local age_hours=$(( (current_time - file_time) / 3600 ))
    
    echo $age_hours
}

check_file_size() {
    local file=$1
    
    if [ ! -f "$file" ]; then
        return 1
    fi
    
    # File size in MB
    local size_bytes=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file")
    local size_mb=$(( size_bytes / 1024 / 1024 ))
    
    echo $size_mb
}

# ============================================================================
# POSTGRESQL BACKUP CHECK
# ============================================================================

log "🔍 Checking PostgreSQL backups..."

POSTGRES_ISSUES=0

# Find latest backup
LATEST_PG_BACKUP=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f 2>/dev/null | sort -r | head -1)

if [ -z "$LATEST_PG_BACKUP" ]; then
    error "No PostgreSQL backups found in $BACKUP_DIR"
    POSTGRES_ISSUES=$((POSTGRES_ISSUES + 1))
else
    log "Latest backup: $(basename "$LATEST_PG_BACKUP")"
    
    # Check age
    AGE_HOURS=$(check_file_age "$LATEST_PG_BACKUP" $MAX_AGE_HOURS)
    log "Age: ${AGE_HOURS} hours"
    
    if [ $AGE_HOURS -gt $MAX_AGE_HOURS ]; then
        warn "PostgreSQL backup is too old (${AGE_HOURS}h > ${MAX_AGE_HOURS}h)"
        POSTGRES_ISSUES=$((POSTGRES_ISSUES + 1))
    else
        log "✅ Age is acceptable"
    fi
    
    # Check size
    SIZE_MB=$(check_file_size "$LATEST_PG_BACKUP")
    SIZE_HR=$(du -h "$LATEST_PG_BACKUP" | cut -f1)
    log "Size: $SIZE_HR (${SIZE_MB}MB)"
    
    if [ $SIZE_MB -lt $MIN_SIZE_MB ]; then
        warn "PostgreSQL backup size is suspiciously small (${SIZE_MB}MB < ${MIN_SIZE_MB}MB)"
        POSTGRES_ISSUES=$((POSTGRES_ISSUES + 1))
    else
        log "✅ Size is acceptable"
    fi
    
    # Check integrity
    log "Checking integrity..."
    if gunzip -t "$LATEST_PG_BACKUP" 2>/dev/null; then
        log "✅ Backup integrity OK"
    else
        error "PostgreSQL backup is corrupted!"
        POSTGRES_ISSUES=$((POSTGRES_ISSUES + 1))
    fi
    
    # Count total backups
    TOTAL_PG_BACKUPS=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f 2>/dev/null | wc -l)
    log "Total backups: $TOTAL_PG_BACKUPS"
    
    # Show disk usage
    TOTAL_PG_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
    log "Total disk usage: $TOTAL_PG_SIZE"
fi

# ============================================================================
# MEDIA BACKUP CHECK
# ============================================================================

log ""
log "🔍 Checking Media backups..."

MEDIA_ISSUES=0

# Find latest media backup
LATEST_MEDIA_BACKUP=$(find "$MEDIA_BACKUP_DIR" -name "media_backup_*.tar.gz" -type f 2>/dev/null | sort -r | head -1)

if [ -z "$LATEST_MEDIA_BACKUP" ]; then
    warn "No media backups found in $MEDIA_BACKUP_DIR"
    log "   (This is OK if media backups run weekly)"
else
    log "Latest backup: $(basename "$LATEST_MEDIA_BACKUP")"
    
    # Check age (more tolerant for weekly backups)
    MAX_MEDIA_AGE_HOURS=192  # 8 days (weekly + 1 day tolerans)
    AGE_HOURS=$(check_file_age "$LATEST_MEDIA_BACKUP" $MAX_MEDIA_AGE_HOURS)
    log "Age: ${AGE_HOURS} hours"
    
    if [ $AGE_HOURS -gt $MAX_MEDIA_AGE_HOURS ]; then
        warn "Media backup is too old (${AGE_HOURS}h > ${MAX_MEDIA_AGE_HOURS}h)"
        MEDIA_ISSUES=$((MEDIA_ISSUES + 1))
    else
        log "✅ Age is acceptable"
    fi
    
    # Check size
    SIZE_MB=$(check_file_size "$LATEST_MEDIA_BACKUP")
    SIZE_HR=$(du -h "$LATEST_MEDIA_BACKUP" | cut -f1)
    log "Size: $SIZE_HR (${SIZE_MB}MB)"
    
    # Check integrity
    log "Checking integrity..."
    if tar -tzf "$LATEST_MEDIA_BACKUP" >/dev/null 2>&1; then
        log "✅ Backup integrity OK"
    else
        error "Media backup is corrupted!"
        MEDIA_ISSUES=$((MEDIA_ISSUES + 1))
    fi
    
    # Count total backups
    TOTAL_MEDIA_BACKUPS=$(find "$MEDIA_BACKUP_DIR" -name "media_backup_*.tar.gz" -type f 2>/dev/null | wc -l)
    log "Total backups: $TOTAL_MEDIA_BACKUPS"
    
    # Show disk usage
    TOTAL_MEDIA_SIZE=$(du -sh "$MEDIA_BACKUP_DIR" 2>/dev/null | cut -f1)
    log "Total disk usage: $TOTAL_MEDIA_SIZE"
fi

# ============================================================================
# DISK SPACE CHECK
# ============================================================================

log ""
log "🔍 Checking disk space..."

# Get available disk space
if command -v df >/dev/null 2>&1; then
    BACKUP_DISK=$(df -h "$BACKUP_DIR" 2>/dev/null | tail -1)
    DISK_USAGE=$(echo "$BACKUP_DISK" | awk '{print $5}' | tr -d '%')
    DISK_AVAIL=$(echo "$BACKUP_DISK" | awk '{print $4}')
    
    log "Disk usage: ${DISK_USAGE}%"
    log "Available: $DISK_AVAIL"
    
    if [ $DISK_USAGE -gt 90 ]; then
        error "Disk space critical! ${DISK_USAGE}% used"
        POSTGRES_ISSUES=$((POSTGRES_ISSUES + 1))
    elif [ $DISK_USAGE -gt 80 ]; then
        warn "Disk space running low: ${DISK_USAGE}% used"
    else
        log "✅ Disk space OK"
    fi
fi

# ============================================================================
# SUMMARY
# ============================================================================

log ""
log "═══════════════════════════════════════════════════════"
log "📊 BACKUP HEALTH CHECK SUMMARY"
log "═══════════════════════════════════════════════════════"

TOTAL_ISSUES=$((POSTGRES_ISSUES + MEDIA_ISSUES))

if [ $POSTGRES_ISSUES -eq 0 ]; then
    log "✅ PostgreSQL Backups: HEALTHY"
else
    log "❌ PostgreSQL Backups: $POSTGRES_ISSUES issue(s) found"
fi

if [ -z "$LATEST_MEDIA_BACKUP" ]; then
    log "⏭️  Media Backups: Not checked (no backups found)"
elif [ $MEDIA_ISSUES -eq 0 ]; then
    log "✅ Media Backups: HEALTHY"
else
    log "❌ Media Backups: $MEDIA_ISSUES issue(s) found"
fi

log "═══════════════════════════════════════════════════════"

# Send alert if issues found
if [ $TOTAL_ISSUES -gt 0 ]; then
    log "❌ BACKUP HEALTH CHECK FAILED ($TOTAL_ISSUES issues)"
    
    if [ -n "$NOTIFY_EMAIL" ]; then
        send_alert "⚠️ Backup Health Check Failed" "Backup health check found $TOTAL_ISSUES issue(s).

PostgreSQL Issues: $POSTGRES_ISSUES
Media Issues: $MEDIA_ISSUES

Please review backup logs and take action."
    fi
    
    exit 1
else
    log "✅ ALL BACKUP CHECKS PASSED"
    exit 0
fi
