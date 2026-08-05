#!/bin/bash
# NOTICE — Suricata Rule Auto-Update Script
# Run via cron: 0 4 * * * /home/notice/Documents/notice/update_rules.sh
#
# What it does:
# 1. Runs suricata-update to download latest ET Pro rules
# 2. Preserves custom local.rules
# 3. Validates the new ruleset
# 4. Reloads Suricata if validation passes
# 5. Logs results

LOG="/var/log/notice-rule-update.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOCAL_RULES="/var/lib/suricata/rules/local.rules"

echo "[$TIMESTAMP] === Rule Update Started ===" >> "$LOG"

# Backup local rules
if [ -f "$LOCAL_RULES" ]; then
    cp "$LOCAL_RULES" "/tmp/local.rules.backup.$(date +%Y%m%d)"
    echo "[$TIMESTAMP] Backed up local.rules" >> "$LOG"
fi

# Run suricata-update
echo "[$TIMESTAMP] Running suricata-update..." >> "$LOG"
suricata-update >> "$LOG" 2>&1
UPDATE_STATUS=$?

if [ $UPDATE_STATUS -ne 0 ]; then
    echo "[$TIMESTAMP] ERROR: suricata-update failed (exit code $UPDATE_STATUS)" >> "$LOG"
    exit 1
fi

# Restore local rules if they were overwritten
if [ -f "/tmp/local.rules.backup.$(date +%Y%m%d)" ]; then
    cp "/tmp/local.rules.backup.$(date +%Y%m%d)" "$LOCAL_RULES"
    echo "[$TIMESTAMP] Restored local.rules" >> "$LOG"
fi

# Validate rules
echo "[$TIMESTAMP] Validating ruleset..." >> "$LOG"
suricata -T -c /etc/suricata/suricata.yaml -l /tmp 2>> "$LOG"
VALIDATE_STATUS=$?

if [ $VALIDATE_STATUS -ne 0 ]; then
    echo "[$TIMESTAMP] ERROR: Rule validation failed. NOT reloading." >> "$LOG"
    exit 1
fi

# Reload Suricata (send SIGUSR2 for live rule reload)
echo "[$TIMESTAMP] Reloading Suricata rules..." >> "$LOG"
kill -USR2 $(pidof suricata) 2>> "$LOG"
RELOAD_STATUS=$?

if [ $RELOAD_STATUS -eq 0 ]; then
    echo "[$TIMESTAMP] Rules reloaded successfully." >> "$LOG"
else
    echo "[$TIMESTAMP] WARNING: Suricata reload signal failed (may need restart)" >> "$LOG"
fi

# Count rules
RULE_COUNT=$(grep -c '^alert\|^drop\|^reject' /var/lib/suricata/rules/*.rules 2>/dev/null | tail -1 | cut -d: -f2)
CUSTOM_COUNT=$(grep -c '^alert' "$LOCAL_RULES" 2>/dev/null)
echo "[$TIMESTAMP] Total rules: $RULE_COUNT | Custom rules: $CUSTOM_COUNT" >> "$LOG"
echo "[$TIMESTAMP] === Rule Update Complete ===" >> "$LOG"
echo "" >> "$LOG"
