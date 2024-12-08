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
LOG_FILE="$HOME/.vt_scan.log"   # File where results will be logged
onlyCheckExisting=false         # Set to true if you want to only check existing files, false to scan new files.
deleteMalware=true              # Set to true to delete malware-infected files

# Ensure VirusTotal CLI is configured
if ! command -v vt &>/dev/null; then
    log_error "Error: vt CLI is not installed or not in PATH"
    exit 1
fi

log_info "Monitoring $MONITOR_DIR for new files..."

# Monitor directory for new files
inotifywait -m -e create --format "%w%f" "$MONITOR_DIR" 2>/dev/null | while read NEW_FILE; do
    # Skip incomplete or temporary files
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
            log_debug "Checking last analysis stats for file hash $FILE_HASH in VirusTotal's database..."
            ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)
            
            if [[ $? -ne 0 ]]; then
                log_error "Failed to retrieve analysis stats for $NEW_FILE."
                continue
            fi

            echo "$ANALYSIS_STATS" >> "$LOG_FILE"

            # Log the full analysis stats for debugging
            log_debug "Full Analysis Stats: $ANALYSIS_STATS"

            # Check if the ANALYSIS_STATS is valid JSON
            echo "$ANALYSIS_STATS" | jq . > /dev/null
            if [ $? -ne 0 ]; then
                log_error "Error: Invalid JSON received from VirusTotal for $NEW_FILE"
                continue
            fi

            MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.last_analysis_stats.malicious // "0"')
            SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.last_analysis_stats.suspicious // "0"')

            # Check if values are not empty before comparing
            if [[ "$MALICIOUS" -gt 0 ]]; then
                log_error "$MALICIOUS malicious findings found for $NEW_FILE."
            elif [[ "$SUSPICIOUS" -gt 0 ]]; then
                log_warning "$SUSPICIOUS suspicious findings found for $NEW_FILE."
            else
                log_success "No issues found for $NEW_FILE in the report."
            fi
        else
            # If not in the database, scan the file
            log_info "File not found in VirusTotal's database, scanning it..."

            SCAN_RESULT=$(vt file scan "$FILE_HASH" -i=last_analysis_stats --format json)

            if [[ $? -ne 0 ]]; then
                log_error "Failed to scan $NEW_FILE."
                continue
            fi

            sleep 5s

            log_info "Retrieving last analysis stats for file $NEW_FILE with hash $FILE_HASH..."
            ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)

            if [[ $? -ne 0 ]]; then
                log_error "Failed to retrieve analysis stats after scanning $NEW_FILE."
                continue
            fi

            echo "$SCAN_RESULT" >> "$LOG_FILE"
            echo "$ANALYSIS_STATS" >> "$LOG_FILE"

            # Log the full analysis stats for debugging
            log_debug "Full Analysis Stats: $ANALYSIS_STATS"

            # If the scan result is "Resource not found", wait and query the stats again
            if echo "$SCAN_RESULT" | grep -q "Resource not found"; then
                log_debug "Scan result: Resource not found. Waiting for the scan report..."

                # Retry the stats query in case of a timeout
                RETRY_COUNT=0
                MAX_RETRIES=5
                while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
                    log_debug "Retrying stats query (Attempt: $((RETRY_COUNT+1)))..."
                    sleep 10  # Wait for 10 seconds before retrying

                    ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)

                    if [[ $? -ne 0 ]]; then
                        log_error "Failed to retrieve analysis stats during retry."
                        break
                    fi

                    echo "$ANALYSIS_STATS" >> "$LOG_FILE"

                    MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.malicious // "0"')
                    MALICIOUS2=$(echo "$ANALYSIS_STATS" | jq -r '.[] // "0"')
                    SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.suspicious // "0"')

                    # Check if values are not empty before comparing
                    if [[ "$MALICIOUS" -gt 0 ]]; then
                        log_error "$MALICIOUS malicious findings found for $NEW_FILE."
                        break
                    elif [[ "$SUSPICIOUS" -gt 0 ]]; then
                        log_warning "$SUSPICIOUS suspicious findings found for $NEW_FILE."
                        break
                    else
                        log_success "No issues found for $NEW_FILE in the report."
                    fi
                    ((RETRY_COUNT++))
                done
            else
              # If stats are found, check them immediately
              MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.malicious // "0"')
              SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.suspicious // "0"')

              # Check if values are not empty before comparing
              if [[ "$MALICIOUS" -gt 0 ]]; then
                  log_error "Warning: Malware found in $NEW_FILE. Malicious findings: $MALICIOUS."
              elif [[ "$SUSPICIOUS" -gt 0 ]]; then
                  log_warning "$SUSPICIOUS suspicious findings found for $NEW_FILE."
              else
                  log_success "Scan completed for $NEW_FILE. No issues found."
              fi
            fi
        fi
    else
        log_info "Skipped $NEW_FILE (not a regular file)."
    fi
done
