"""
This script is a CLI tool that allows users to scan
APK files and Docker images for security vulnerabilities
using MobSF and Trivy
"""
import os
import subprocess
import sys

import click

from utils import (
    upload,
    process_response,
    compare_reports,
)

from shell_escape_finder import scan_repo, print_report

from initialization import init_mobsf, install_trivy


@click.group()
def main():
    """
    CLI tool for scanning APK files and
    Docker images for security vulnerabilities.
    """


@main.group()
def docker():
    """Commands for scanning Docker images for security vulnerabilities."""


@main.group()
def mobile():
    """Commands for scanning APK files for security vulnerabilities."""


@main.group()
def code():
    """Commands for scanning code for security vulnerabilities."""


# ------------------------------- MOBSF Command -------------------------------
@mobile.command()
def mobsf_init():
    """Initialize the MobSF Docker container."""
    init_mobsf()


@mobile.command()
@click.argument('files', nargs=-1)
@click.option('--apikey', envvar='MOBSF_APIKEY', prompt=True, help='API key for authentication')
@click.option('--pdf', help='Generate PDF report')
def mobsf(files, apikey, pdf):
    """Scan and analyze APK files for security vulnerabilities using MobSF."""
    if not files:
        files = []
        file1 = click.prompt("Enter the file path")
        file2 = click.prompt("Enter the file path of another apk package, enter 'n' to skip")
        files.append(file1)
        if file2 != "n":
            files.append(file2)

    responses = [upload(file, apikey) for file in files]

    for response in responses:
        process_response(response, apikey, pdf)

    if len(files) == 2 and not pdf:
        compare_reports(responses, apikey)


# ------------------------------- Docker Command -------------------------------
@docker.command()
def trivy_install():
    """Install Trivy for scanning Docker images."""
    install_trivy()


@docker.command()
@click.option('--name', prompt=True, help='Name of the Docker image to scan')
@click.option("--html", help="Specify the location to the HTML template file")
def trivy(name, html):
    """Run Trivy scan for a Docker image."""
    if html:
        trimmed_name = name.split("/")[-1]
        # Define the Trivy command
        output_file = f"{trimmed_name}.html"
        template_path = html
        cmd = [
            "trivy", "image",
            "--format", "template",
            "--template", f"@{template_path}",
            "-o", output_file,
            name
        ]
    else:
        cmd = ["trivy", "image", name]

    # Execute the Trivy command
    try:
        subprocess.run(cmd, check=True)
        click.echo("Scan completed successfully")
        if html:
            click.echo(f"The report is saved to {output_file}")
    except subprocess.CalledProcessError as e:
        click.echo("Trivy scan failed")
        click.echo(f"Details: {str(e)}")


# ------------------------------- Code Command -------------------------------
@code.command()
def bandit():
    """Run Bandit to check Python code for security vulnerabilities."""
    path = input("Enter the path to the Python code: ")
    subprocess.run(['bandit', '-c', 'bandit.yaml', '-r', '-ll', path], check=True)


@code.command()
def shell_escape():
    """Scan code for potential shell escape vulnerabilities."""
    repo_path = input("Enter the path to the repository: ").strip()
    repo_path = os.path.expanduser(repo_path)  # Expand the tilde to the full home directory path
    if not os.path.isdir(repo_path):
        print("The provided path is not a directory.")
        sys.exit(1)

    vulnerabilities = scan_repo(repo_path)
    print_report(vulnerabilities)


if __name__ == '__main__':
    main()
