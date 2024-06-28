"""
This script is a CLI tool that allows users to scan
APK files and Docker images for security vulnerabilities
using MobSF and Trivy
"""
import os
import subprocess
import sys

import tempfile

import click

from ingysec.utils import (
    upload,
    process_response,
    compare_reports,
)

from ingysec.shell_escape_finder import scan_repo, print_report, download_repo

from ingysec.initialization import init_mobsf, install_trivy, install_bandit


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
@click.option('--pdf',
              help='Generate PDF report, takes an argument of the name of the generated PDF file')
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
@click.option('--image', prompt=True, help='Name or ID of the Docker image to scan')
@click.option("--html", help="Specify the location to the HTML template file")
def trivy(image, html):
    """Run Trivy scan for a Docker image."""
    if html:
        trimmed_name = image.split("/")[-1]
        # Define the Trivy command
        output_file = f"{trimmed_name}.html"
        template_path = html
        cmd = [
            "trivy", "image",
            "--format", "template",
            "--template", f"@{template_path}",
            "-o", output_file,
            image
        ]
    else:
        cmd = ["trivy", "image", image]

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
def bandit_install():
    """Install Bandit."""
    install_bandit()


@code.command()
def bandit():
    """Run Bandit to check Python code for security vulnerabilities."""
    path = input("Enter the path to the Python code: ")
    subprocess.run(['bandit', '-c', 'bandit.yaml', '-r', '-ll', path], check=True)


@code.command()
@click.argument('repo')
@click.option('--seckey',
              type=click.Path(exists=True),
              help='Path to the SSH private key for cloning the repository.')
def shell_escape(repo, seckey):
    """
    Scan a local or remote repository for potential shell escape vulnerabilities.

    REPO_INPUT can be a path to a local repository or a URL of a remote repository.
    """
    # Check if the input is a URL (starts with http, https, or git@)
    if repo.startswith(("http://", "https://", "git@")):
        with tempfile.TemporaryDirectory() as tmpdirname:
            print(f"Cloning remote repository to temporary directory: {tmpdirname}")
            download_repo(repo, tmpdirname, seckey)
            vulnerabilities = scan_repo(tmpdirname)
    else:
        # Assuming the input is a local path
        if not os.path.isdir(repo):
            print("The provided path is not a directory.")
            sys.exit(1)
        vulnerabilities = scan_repo(repo)

    print_report(vulnerabilities)


if __name__ == '__main__':
    main()
