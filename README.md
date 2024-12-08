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

4. Set Up VirusTotal API Key

To use the VirusTotal scanning feature in the AutoVTScanner, you need to set up a VirusTotal API key. Follow these steps to get started:

### 1. **Obtain a VirusTotal API Key**

- Visit [VirusTotal](https://www.virustotal.com/) and create an account or log in if you already have one.
- Once logged in, go to the [API Key page](https://www.virustotal.com/ui/apikey) and copy your API key.

### 2. **Initialize the API Key**

After obtaining your API key, you need to initialize it in the VirusTotal CLI tool. Run the following command in your terminal:

```bash
vt init --apikey YOUR_API_KEY
```

6. Run the script:

```bash
./scanner.sh
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the [MIT](./LICENSE) License.
