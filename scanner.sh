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
  if [[ "$DEBUG" == "true" ]]; then
    echo -e "${GREEN}$(timestamp) ${WHITE}[DEBUG]${RESET} $1"
  fi
}

show_help() {
  echo -e "${WHITE}Usage: ${BLUE}$0 ${WHITE}[${GREEN}options${WHITE}]${RESET}"
  echo -e "${WHITE}Options:"
  echo -e "  ${GREEN}--help          ${WHITE}Show this help message."
  echo -e "  ${GREEN}--version       ${WHITE}Show script version."
  echo -e "  ${GREEN}--delete        ${WHITE}Enable malware file deletion."
  echo -e "  ${GREEN}--debug         ${WHITE}Toggle the DEBUG option."
  echo -e "  ${GREEN}--folder ${YELLOW}<DIR>  ${WHITE}Change the directory to monitor for new files."
}

send_notification() {
  local title="$1"
  local message="$2"
  notify-send -a "Malware Alert" -u critical -i "dialog-information" "$title" "$message"
}

# Locals
CONFIG_FILE="$HOME/.vt_scan.config"
LOG_FILE="$HOME/.vt_scan.log"
script_version="1.0"
DEFAULT_CONFIG='{
  "DEBUG": false,
  "MONITOR_DIR": "$HOME/Downloads",
  "onlyCheckExisting": false,
  "deleteMalware": false
}'

# if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
  log_info "${WHITE}Configuration file not found. Creating a new config file with default values."
  echo "$DEFAULT_CONFIG" | sed "s|\$HOME|$HOME|g" >"$CONFIG_FILE"
  log_debug "${WHITE}Config file created at ${GREEN}$CONFIG_FILE${WHITE}."
fi

if ! command -v vt &>/dev/null; then
  log_error "VirusTotal CLI is not installed. You can install it using the following command:"
  log_error "sudo apt-get install vt-cli"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  log_error "jq is not installed. Please install it using: sudo apt-get install jq"
  exit 1
fi

load_config() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    # If config doesn't exist, create it
    log_info "Configuration file not found. Creating a new config file with default values."
    echo "$DEFAULT_CONFIG" | sed "s|\$HOME|$HOME|g" >"$CONFIG_FILE"
    log_debug "Config file created at $CONFIG_FILE."
  fi

  # Parse JSON config and export variables
  DEBUG=$(jq -r '.DEBUG' "$CONFIG_FILE")
  MONITOR_DIR=$(jq -r '.MONITOR_DIR' "$CONFIG_FILE")
  onlyCheckExisting=$(jq -r '.onlyCheckExisting' "$CONFIG_FILE")
  deleteMalware=$(jq -r '.deleteMalware' "$CONFIG_FILE")
}

toggle_delete_malware() {
  current_value=$(jq -r '.deleteMalware' "$CONFIG_FILE")

  if [[ "$current_value" == "true" ]]; then
    log_debug "Disabling deleteMalware..."
    jq '.deleteMalware = false' "$CONFIG_FILE" >"$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
  elif [[ "$current_value" == "false" ]]; then
    log_debug "Enabling deleteMalware..."
    jq '.deleteMalware = true' "$CONFIG_FILE" >"$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
  else
    log_error "Error: Unable to read the current value of deleteMalware."
    exit 1
  fi

  log_info "deleteMalware is now set to $(jq -r '.deleteMalware' "$CONFIG_FILE")."
}

toggle_debug() {
  current_value=$(jq -r '.DEBUG' "$CONFIG_FILE")

  if [[ "$current_value" == "true" ]]; then
    log_debug "Disabling DEBUG..."
    jq '.DEBUG = false' "$CONFIG_FILE" >"$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
  elif [[ "$current_value" == "false" ]]; then
    log_debug "Enabling DEBUG..."
    jq '.DEBUG = true' "$CONFIG_FILE" >"$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
  else
    log_error "Error: Unable to read the current value of DEBUG."
    exit 1
  fi

  log_info "DEBUG is now set to $(jq -r '.DEBUG' "$CONFIG_FILE")."
}

update_config_value() {
  local key="$1"
  local value="$2"
  jq ".$key = \"$value\"" "$CONFIG_FILE" >"$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
}

change_monitor_dir() {
  local new_dir="$1"
  if [[ -d "$new_dir" ]]; then
    update_config_value "MONITOR_DIR" "$new_dir"
    log_success "MONITOR_DIR updated to: $new_dir"
  else
    log_error "Directory '$new_dir' does not exist. Please provide a valid path."
    exit 1
  fi
}

load_config
case "$1" in
--help)
  show_help
  exit 0
  ;;
--version)
  echo -e "${WHITE}Script version: ${GREEN}$script_version${RESET}"
  exit 0
  ;;
--delete)
  toggle_delete_malware
  exit 0
  ;;
--debug)
  toggle_debug
  exit 0
  ;;
--folder)
  if [[ -n "$2" ]]; then
    change_monitor_dir "$2"
    exit 0
  else
    log_error "No directory specified for --folder."
    exit 1
  fi
  ;;
esac

log_info "Monitoring $MONITOR_DIR for new files..."
inotifywait -m -e create --format "%w%f" "$MONITOR_DIR" 2>/dev/null | while read NEW_FILE; do
  # Skip incomplete or temporary
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

    # Check if file hash exists in VT's DB
    if [[ "$onlyCheckExisting" == true ]]; then
      log_debug "Checking last analysis stats for file hash $FILE_HASH in VirusTotal's database..."
      ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)

      if [[ $? -ne 0 ]]; then
        log_error "Failed to retrieve analysis stats for $NEW_FILE."
        continue
      fi

      echo "$ANALYSIS_STATS" >>"$LOG_FILE"

      # Log full stats for debugging
      log_debug "Full Analysis Stats: $ANALYSIS_STATS"

      # Check if ANALYSIS_STATS is valid
      echo "$ANALYSIS_STATS" | jq . >/dev/null
      if [ $? -ne 0 ]; then
        log_error "Error: Invalid JSON received from VirusTotal for $NEW_FILE"
        continue
      fi

      MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.malicious // "0"')
      SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.suspicious // "0"')

      # Check if values are not empty
      if [[ "$MALICIOUS" -gt 0 ]]; then
        log_error "$MALICIOUS malicious findings found for $NEW_FILE."
        if [[ "$deleteMalware" == true ]]; then
          log_info "Deleting malware-infected file: $NEW_FILE"
          rm -f "$NEW_FILE"
          log_success "File deleted: $NEW_FILE"
          send_notification "Malware Found" "Malware found and deleted file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
        else
          send_notification "Malware Found" "Malware found in file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
        fi

      elif [[ "$SUSPICIOUS" -gt 0 ]]; then
        log_warning "$SUSPICIOUS suspicious findings found for $NEW_FILE."
        send_notification "Suspicious File Detected" "Suspicious file detected: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
      else
        log_success "No issues found for $NEW_FILE in the report."
      fi
    else
      # If not in the db, scan file
      log_info "File not found in VirusTotal's database, scanning it..."

      SCAN_RESULT=$(vt file scan "$FILE_HASH" -i=last_analysis_stats --format json)

      if [[ $? -ne 0 ]]; then
        log_error "Failed to scan $NEW_FILE."
        continue
      fi

      sleep 2s

      log_debug "Retrieving last analysis stats for file $NEW_FILE with hash $FILE_HASH..."
      ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)

      if [[ $? -ne 0 ]]; then
        log_error "Failed to retrieve analysis stats after scanning $NEW_FILE."
        continue
      fi

      echo "$SCAN_RESULT" >>"$LOG_FILE"
      echo "$ANALYSIS_STATS" >>"$LOG_FILE"

      log_debug "Full Analysis Stats: $ANALYSIS_STATS"

      # If scan result is "Resource not found", wait and query again
      if echo "$SCAN_RESULT" | grep -q "Resource not found"; then
        log_debug "Scan result: Resource not found. Waiting for the scan report..."

        # Retry the stats query in case of timeout
        RETRY_COUNT=0
        MAX_RETRIES=5
        while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
          log_debug "Retrying stats query (Attempt: $((RETRY_COUNT + 1)))..."
          sleep 10 # Wait 10 seconds before retrying

          ANALYSIS_STATS=$(vt file "$FILE_HASH" -i=last_analysis_stats --format json)

          if [[ $? -ne 0 ]]; then
            log_error "Failed to retrieve analysis stats during retry."
            break
          fi

          echo "$ANALYSIS_STATS" >>"$LOG_FILE"

          MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.malicious // "0"')
          SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.suspicious // "0"')

          # Check if values not empty
          if [[ "$MALICIOUS" -gt 0 ]]; then
            log_error "$MALICIOUS malicious findings found for $NEW_FILE."
            if [[ "$deleteMalware" == true ]]; then
              log_info "Deleting malware-infected file: $NEW_FILE"
              rm -f "$NEW_FILE"
              log_success "File deleted: $NEW_FILE"
              send_notification "Malware Found" "Malware found and deleted file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
            else
              send_notification "Malware Found" "Malware found in file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
            fi

            break
          elif [[ "$SUSPICIOUS" -gt 0 ]]; then
            log_warning "$SUSPICIOUS suspicious findings found for $NEW_FILE."
            send_notification "Suspicious File Detected" "Suspicious file detected: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
            break
          else
            log_success "No issues found for $NEW_FILE in the report."
          fi
          ((RETRY_COUNT++))
        done
      else
        # If stats found
        MALICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.malicious // "0"')
        SUSPICIOUS=$(echo "$ANALYSIS_STATS" | jq -r '.[].last_analysis_stats.suspicious // "0"')

        # Check if values not empty
        if [[ "$MALICIOUS" -gt 0 ]]; then
          log_error "Warning: Malware found in $NEW_FILE. Malicious findings: $MALICIOUS."
          if [[ "$deleteMalware" == true ]]; then
            log_info "Deleting malware-infected file: $NEW_FILE"
            rm -f "$NEW_FILE"
            log_success "File deleted: $NEW_FILE"
            send_notification "Malware Found" "Malware found and deleted file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
          else
            send_notification "Malware Found" "Malware found in file: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
          fi
        elif [[ "$SUSPICIOUS" -gt 0 ]]; then
          log_warning "Suspicious file detected: $NEW_FILE."
          send_notification "Suspicious File Detected" "Suspicious file detected: $NEW_FILE \nVisit the report: https://www.virustotal.com/gui/file/$FILE_HASH"
        else
          log_success "No issues found for $NEW_FILE in the report."
        fi
      fi
    fi
  fi
done
