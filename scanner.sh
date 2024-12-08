#!/bin/bash

# Directory to monitor
MONITOR_DIR="$HOME/Downloads"
LOG_FILE="$HOME/.vt_scan.log"

# Ensure VirusTotal CLI is configured
if ! command -v vt &>/dev/null; then
    echo "Error: vt CLI is not installed or not in PATH." >&2
    exit 1
fi

echo "Monitoring $MONITOR_DIR for new files..."

# Monitor directory for new files
inotifywait -m -e create --format "%w%f" "$MONITOR_DIR" | while read NEW_FILE; do
    echo "New file detected: $NEW_FILE"
    if [[ -f "$NEW_FILE" ]]; then
        echo "Scanning $NEW_FILE with VirusTotal..."
        vt file scan "$NEW_FILE" >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            echo "Scan completed for $NEW_FILE. Results logged."
        else
            echo "Failed to scan $NEW_FILE. Check log for details."
        fi
    else
        echo "Skipped $NEW_FILE (not a regular file)."
    fi
done
