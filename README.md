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

#### Initialization
This command will initialize the MobSF docker container and run it on port 3000. It will also provide the API key for the MobSF server.
```shell
ingysec mobile mobsf_init
```

#### Scan APK Files

```sh
python cli_tool.py mobile mobsf --apikey YOUR_API_KEY --pdf output.pdf path/to/file1.apk path/to/file2.apk
```

- `files`: Paths to APK files.
- `--apikey`: API key for MobSF authentication. Or set the `MOBSF_APIKEY` environment variable.
- `--pdf`: Optional. If specified, generates a PDF report.

### Trivy Commands

Run Trivy scan for a Docker image.

#### Installation
This command will install Trivy on your system. Only run it once, and it only works on **Linux(Debian/Ubuntu)** systems.
```shell
ingysec cloud trivy_install
```

#### Scan Docker Images

```sh
python cli_tool.py cloud trivy --name IMAGE_NAME --html template.html
```

- `--name`: Name of the Docker image to scan.
- `--html`: Optional. Path to an HTML template file for generating the report. If not present, the results will be
    displayed in the terminal as a table.

### Code Commands
Run code inspection and scanning commands to detect security vulnerabilities in Python code.

#### Bandit
Run Bandit to check Python code for security vulnerabilities.

```sh
ingysec code bandit
```
Prompts the user to enter the path to the Python code.
Recursively scans all Python files in the specified path using the Bandit configuration file bandit.yaml.
Sets the severity level to high (-ll) and reports all discovered security issues.

#### Shell Escape
Scan code for potential shell escape vulnerabilities.

```sh
ingysec code shell_escape
```
Prompts the user to enter the path to the repository.
Expands ~ to the full home directory path and verifies that the provided path is a directory.

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

## Extending the Tool

### Adding New Commands
To implement a new command, create a new command group in `ingysec/ingy.py`:
```python
@main.group()
def example_command():
"""This is an example command group."""
    pass
```

Then, add a new command to the group:
```python
@example_command.command()
def new_command():
"""This is a new command."""
    pass
```

### Adding New Functions
For the purpose of maintainability and clean code, add new functions to the `utils.py` file.

### Extending `shell_escape_finder.py`
To extend the script to support more languages, you need to update two main components:

1. **File Extensions**: Add the file extensions of the new languages to the `FILE_EXTENSIONS` list.
2. **Patterns**: Add regex patterns to identify potential shell escape vulnerabilities in the `PATTERNS` dictionary.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
