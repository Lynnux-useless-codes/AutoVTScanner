#!/bin/bash

# Logging system
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
WHITE='\033[0;37m'
RESET='\033[0m'

timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

log_info() {
  echo -e "${GREEN}$(timestamp) ${WHITE}[${BLUE}INFO${WHITE}]${RESET} $1"
}

log_success() {
  echo -e "${GREEN}$(timestamp) ${WHITE}[${GREEN}SUCCESS${WHITE}]${RESET} $1"
}

log_warning() {
  echo -e "${GREEN}$(timestamp) ${WHITE}[${YELLOW}WARNING${WHITE}]${RESET} $1"
}

log_error() {
  echo -e "${GREEN}$(timestamp) ${WHITE}[${RED}ERROR${WHITE}]${RESET} $1"
}

log_debug() {
  echo -e "${GREEN}$(timestamp) ${WHITE}[${WHITE}DEBUG${WHITE}]${RESET} $1"
}

# Directory to monitor
DEBUG=true
MONITOR_DIR="$HOME/Downloads"
LOG_FILE="$HOME/.vt_scan.log"
onlyCheckExisting=false  # Set to true if you want to only check existing files, false to scan new files.

# Ensure VirusTotal CLI is configured
if ! command -v vt &>/dev/null; then
    log_error "Error: vt CLI is not installed or not in PATH"
    exit 1
fi

log_info "Monitoring $MONITOR_DIR for new files..."

# Monitor directory for new files
inotifywait -m -e create --format "%w%f" "$MONITOR_DIR" 2>/dev/null | while read NEW_FILE; do
    # Skip files
    if [[ "$NEW_FILE" == *.crdownload || "$NEW_FILE" == "$MONITOR_DIR"/.com.google.Chrome* ]]; then
        log_debug "Skipping incomplete or temporary file: $NEW_FILE"
        continue
    fi
    sleep 1s

    log_info "New file detected: $NEW_FILE"
    if [[ -f "$NEW_FILE" ]]; then
        log_debug "Hashing file: $NEW_FILE"
        FILE_HASH=$(sha256sum "$NEW_FILE" | awk '{ print $1 }')
        log_debug "Calculated SHA256 hash: $FILE_HASH"

        log_debug "Checking if $NEW_FILE exists in VirusTotal's database..."

        # Check if the file hash exists in VirusTotal's database
        if [[ "$onlyCheckExisting" == true ]]; then
            log_debug "Checking report for file hash $FILE_HASH in VirusTotal's database..."
            REPORT=$(vt file report "$FILE_HASH")

            echo "$REPORT" >> "$LOG_FILE"

            if echo "$REPORT" | grep -q "found"; then
                log_warning "Malicious vendors found for $NEW_FILE in the report."
            else
                log_success "No issues found for $NEW_FILE in the report."
            fi
        else
            # If not in the database, scan the file
            log_info "File not found in VirusTotal's database, scanning it..."

            SCAN_RESULT=$(vt file scan "$NEW_FILE")

            sleep 5s

            log_info "Retrieving report for file $NEW_FILE with hash $FILE_HASH..."
            REPORT=$(vt file report "$FILE_HASH")

            echo "$SCAN_RESULT" >> "$LOG_FILE"

            # If the scan result is "Resource not found", wait and query the report again
            if echo "$SCAN_RESULT" | grep -q "Resource not found"; then
                log_debug "Scan result: Resource not found. Waiting for the scan report..."

                # Wait for the scan to be indexed by VirusTotal (loop until report is found)
                RETRY_COUNT=0
                MAX_RETRIES=5
                while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
                    log_debug "Retrying report query (Attempt: $((RETRY_COUNT+1)))..."
                    sleep 10  # Wait for 10 seconds before retrying

                    REPORT=$(vt file report "$FILE_HASH")
                    echo "$REPORT" >> "$LOG_FILE"

                    # Check if the report has issues
                    if echo "$REPORT" | grep -q "alert_severity: \"high\""; then
                        ISSUES=$(echo "$REPORT" | grep -o "alert_severity: \"high\"" | wc -l)
                        log_warning "$ISSUES high severity issues found for $NEW_FILE."
                    else
                        log_success "No issues found for $NEW_FILE in the report."
                    fi
                    ((RETRY_COUNT++))
                done
            else
                log_debug "Scan completed, checking the report..."
                # If the scan result is found, check it immediately
                REPORT=$(vt file report "$FILE_HASH")
                echo "$REPORT" >> "$LOG_FILE"

                if echo "$REPORT" | grep -q "found"; then
                    ISSUES=$(echo "$REPORT" | grep -o "found" | wc -l)
                    log_warning "$ISSUES issues found for $NEW_FILE."
                else
                    log_success "Scan completed for $NEW_FILE. No issues found."
                fi
            fi
        fi
    else
        log_info "Skipped $NEW_FILE (not a regular file)."
    fi
done
