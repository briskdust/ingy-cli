# Security Scanner CLI Tool

A Command Line Interface (CLI) tool for scanning and analyzing mobile APK files, Docker images and code repository for security vulnerabilities using various security tools.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Mobile Commands](#mobile-commands)
  - [Docker Commands](#docker-commands)
  - [Code Commands](#code-commands)
- [Extending the Tool](#extending-the-tool)
  - [Adding New Commands](#adding-new-commands)
  - [Adding New Functions](#adding-new-functions)
  - [Extending `shell_escape_finder.py`](#extending-shell_escape_finderpy)


## Installation
| :exclamation: Note: Make sure you have Docker installed and running. |
|----------------------------------------------------------------------|

### Install from Source Code
1. **Clone the repository:**

    ```sh
    git clone https://github.com/briskdust/ingy-cli.git
    cd ingy-cli
    ```

2. **Install the required Python packages:**

    ```sh
    poetry install
    ```

3. **Run the CLI tool:**

    ```sh
    python -m ingysec.ingy
    ```

### Install using Pip

1. **Install the tool from PyPI:**

    ```sh
    pip install ingysec
    ```

2. **Run the CLI tool:**

    ```sh
    ingysec
    ```

## Usage

This CLI tool supports multiple commands grouped under `mobile`, `docker`, and `code`.

### Mobile Commands

Scan and analyze APK files for security vulnerabilities using MobSF.

#### Initialization
This command will initialize the MobSF docker container and run it on port 8000. It will also provide the API key for the MobSF server.
```shell
ingysec mobile mobsf_init
```

#### Configuration
Set the `MOBSF_APIKEY` environment variable with your MobSF API key:

```shell
export MOBSF_APIKEY=your_mobsf_api_key
```

#### Scan APK Files

```sh
ingysec mobile mobsf --apikey YOUR_API_KEY --pdf output.pdf path/to/file1.apk path/to/file2.apk
```

- `--apikey`: API key for MobSF authentication. Or set the `MOBSF_APIKEY` environment variable.
- `--pdf`: Optional. If specified, generates a PDF report, otherwise the results will be displayed in terminal as a table.

### Docker Commands

Run Trivy scan for a Docker image.

#### Installation
This command will install Trivy on your system. Only run it once, and it only works on **Linux(Debian/Ubuntu)** systems.
```shell
ingysec docker trivy_install
```

#### Scan Docker Images

```sh
ingysec docker trivy --name IMAGE_NAME --html template.html
```

- `--name`: Name or ID of the Docker image to scan.
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
ingysec code shell-escape REPONAME --seckey PATH
```
The user needs to enter the path to the repository which can also be the URL of a remote repository and utilize the
`--seckey` flag to specify the path to the SSH private key for cloning the repository. Supports shell expansion, such as `~` to the full home directory path and verifies that the provided path is a directory.

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
