# AutoVTScanner

A CLI to automatically check new files for viruses in VirusTotal's api.

## Overview

This project is a Auto VirusTotal CLI Scanner.

It includes a shell script designed to keep checking a single folder for new files and runs them trough the VirusTotal API.

Note that this code is optimized for Ubuntu Environments. `(not tested on other distro's)`

## Getting Started

### Prerequisites

Make sure you have the following installed on your system:

- [vt](https://github.com/VirusTotal/vt-cli): VirusTotal CLI is used to communicate with the VirusTotal API.

```bash
sudo apt install vt-cli
```

- [jq](https://github.com/jqlang/jq): A lightweight and flexible command-line JSON processor.

```bash
sudo apt install jq
```

- [libnotify-bin](https://gitlab.gnome.org/GNOME/libnotify): a library for sending desktop notifications to a notification
daemon.

```bash
sudo apt install libnotify-bin
```

- [inotifywait](https://github.com/inotify-tools/inotify-tools): A tool for monitoring filesystem events in real-time (e.x. File changes).

```bash
sudo apt install inotify-tools
```

- [date](https://github.com/coreutils/coreutils/blob/master/src/date.c) and [sha256sum](https://github.com/coreutils/coreutils/blob/master/tests/cksum/sha256sum.pl): Date is used for Console logging and sha256sum is used to get file hashes.

`(These are typically preinstalled on your device)`

```bash
sudo apt install coreutils
```

### VirusTotal API Key

To use VirusTotal's API, you will need an API key. You can obtain it by creating an account on [VirusTotal](https://www.virustotal.com/) and accessing the API section.

Once you have your API key, you'll need to add it to the configuration:

1. Create a configuration file at ~/.vt_scan.config if it doesn't exist.
2. Add the following line to the file, replacing your_api_key_here with your actual API key:

```bash
vt init --apikey your_api_key_here
```

This will allow the script to authenticate with VirusTotal's API.

### Installation

1. Clone the repository:

```bash
git clone https://github.com/Lynnux-useless-codes/AutoVTScanner.git
cd AutoVTScanner
```

2. Make the scripts executable:

```bash
chmod +x scanner.sh
```

3. Run the setup or primary script:

```bash
./scanner.sh
```

### Usage

Provide examples of how to run the scripts and their expected outputs.

```bash
./scanner.sh [options]
```

#### Options

- `--help`: Display help information about the script.
- `--version`: Show script version.
- `--delete`: Toggle file deletion on malware found. `(default = false)`
- `--debug`: Toggle the DEBUG logs. `(default = false)`
- `--folder <DIR>`: Change the directory of the folder to scan. `(default = $HOME/Downloads)`

### Example

Run the script scanner:

```bash
./scanner.sh
```

Change scan directory:

```bash
./scanner.sh --folder "/home/lynnux/Downloads/Chrome/"
```

### How it works

This script continuously monitors a specified directory for newly created files and checks them against the VirusTotal database for potential malware. The core workflow involves the following steps:

- **Configuration Setup:**
- - The script first checks if a configuration file exists at `~/.vt_scan.config`. If it doesn't, it creates one with default values. You can customize the settings for debugging, monitoring directory, and malware deletion through this configuration.

- **Directory Monitoring:**
- - Using `inotifywait`, the script watches the specified directory (default is `$HOME/Downloads`) for new files. When a new file is detected, it calculates its SHA256 hash and checks whether it's already been analyzed by VirusTotal.

- **VirusTotal Lookup:**
- - If the file hash exists in VirusTotal’s database, the script retrieves its analysis stats. If the file is flagged as malicious or suspicious, it sends a notification and optionally deletes the file.
- - If the file isn’t found in the database, it will be scanned using VirusTotal's scanning API.

- **Malware Handling:**
- - If malware is detected and the `--delete` flag is enabled, the script will delete the file and send a notification. If `--delete` is not enabled, it simply reports the findings without deleting the file.
- - The script also handles scanning retries in case of timeouts during the file analysis retrieval.

- **Command-Line Options:**
- - You can toggle debugging with the `--debug` flag, which enables more detailed logging. Use `--delete` to toggle malware file deletion and `--folder <DIR>` to change the directory being monitored.

- **Notifications:**
- - Notifications are sent using `notify-send`, alerting you when malware or suspicious files are found. It includes links to the VirusTotal report for further details.

### License

This project is licensed under the [MIT License](./LICENSE).
