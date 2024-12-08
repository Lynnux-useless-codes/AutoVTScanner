# AutoVTScanner

AutoVTScanner is a lightweight script that automatically scans newly added files in your `~/Downloads` directory using the VirusTotal CLI.

## Features

- Real-time monitoring of the `~/Downloads` directory.
- Scans new files with VirusTotal.
- Logs results for review.

## Requirements

- Bash
- VirusTotal CLI (`vt`)
- `inotify-tools`

## Installation

1. Install dependencies:

```bash
sudo apt install inotify-tools
```

2. Clone this repository:

```bash
git clone https://github.com/Dark-LYNN/AutoVTScanner.git
cd AutoVTScanner
```

3. Make the script executable:

```bash
chmod +x scanner.sh
```

4. Run the script:

```bash
./scanner.sh
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [MIT](./LICENSE) License.
