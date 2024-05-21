# Security Scanner CLI Tool

A Command Line Interface (CLI) tool for scanning and analyzing mobile APK files and Docker images for security vulnerabilities using MobSF and Trivy.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [MobSF Commands](#mobsf-commands)
  - [Trivy Commands](#trivy-commands)
- [Configuration](#configuration)
- [Functions](#functions)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/briskdust/ingy-cli.git
    cd ingy-cli
    ```

2. **Install the required Python packages:**

    ```sh
    poetry install
    ```

3. **Ensure you have Trivy installed:** 

    Follow the [official Trivy installation guide](https://github.com/aquasecurity/trivy#installation).

## Usage

This CLI tool supports multiple commands grouped under `cloud`, `mobile`, and `gateway`.

### MobSF Commands

Scan and analyze APK files for security vulnerabilities using MobSF.

#### Scan APK Files

```sh
python cli_tool.py mobile mobsf --apikey YOUR_API_KEY --pdf output.pdf path/to/file1.apk path/to/file2.apk
```

- `files`: Paths to APK files.
- `--apikey`: API key for MobSF authentication. Or set the `MOBSF_APIKEY` environment variable.
- `--pdf`: Optional. If specified, generates a PDF report.

### Trivy Commands

Run Trivy scan for a Docker image.

#### Scan Docker Images

```sh
python cli_tool.py cloud trivy --name IMAGE_NAME --html template.html
```

- `--name`: Name of the Docker image to scan.
- `--html`: Optional. Path to an HTML template file for generating the report. If not present, the results will be
    displayed in the terminal as a table.

## Configuration

### MobSF Configuration

- Set the `MOBSF_APIKEY` environment variable with your MobSF API key:

    ```sh
    export MOBSF_APIKEY=your_mobsf_api_key
    ```

### Functions

- `upload(x, apikey)`: Uploads an APK file to the MobSF server.
- `scan(data, apikey)`: Initiates the scan of the uploaded APK file.
- `json_resp(data, apikey)`: Generates a JSON report of the scan.
- `gen_pdf(data, apikey, output_location)`: Generates a PDF report of the scan.
- `compare(hash1, hash2, apikey)`: Compares two APK scans based on their hashes.
- `gen_table(json_dict)`: Generates a table from the JSON report.
- `wrap_text(text, width)`: Wraps text to a specified width.

### Example Commands

#### Upload and Scan APK Files

```sh
python cli_tool.py mobile mobsf path/to/file1.apk --apikey YOUR_API_KEY
```

#### Generate PDF Report

```sh
python cli_tool.py mobile mobsf path/to/file1.apk --apikey YOUR_API_KEY --pdf output.pdf
```

#### Run Trivy Scan

```sh
python cli_tool.py cloud trivy --name docker/image:latest
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
