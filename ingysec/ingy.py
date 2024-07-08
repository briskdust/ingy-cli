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
from jira import JIRA

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


@main.group()
def ticket():
    """Commands for creating Jira tickets."""


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
            "--severity", "HIGH,CRITICAL",
            "-o", output_file,
            image
        ]
    else:
        cmd = ["trivy", "image", "--severity", "HIGH,CRITICAL", image]

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


# ------------------------------- Ticket Command -------------------------------
@ticket.command()
@click.option(
    '--server', envvar='JIRA_SERVER',
    prompt='Jira Server URL', help='Jira Server URL'
)
@click.option(
    '--email', envvar='JIRA_EMAIL',
    prompt='Jira Email', help='Jira Email'
)
@click.option(
    '--api_token', envvar='JIRA_API_TOKEN',
    prompt='Jira API Token', help='Jira API Token'
)
@click.option(
    '--project', prompt='Project Key',
    default='INGY', help='Jira Project Key'
)
@click.option(
    '--summary', prompt='Summary', help='Ticket Summary'
)
@click.option(
    '--description', prompt='Description', help='Ticket Description'
)
@click.option(
    '--issuetype', prompt='Issue Type',
    default='Bug', help='Issue Type (e.g., Bug, Task)'
)
@click.option(
    '--priority', prompt='Priority',
    default='Medium', help='Issue Priority (e.g., Low, Medium, High)'
)
@click.option(
    '--assignee', prompt='Assignee',
    default='', help='Assignee username'
)
def create_ticket(  # pylint: disable=R0913
        server, email, api_token,
        project, summary, description,
        issuetype, priority, assignee
):
    """Create a new Jira ticket."""
    jira_options = {'server': server}
    jira = JIRA(options=jira_options, basic_auth=(email, api_token))

    # List all issue types
    issue_types = jira.issue_types()
    for itype in issue_types:
        click.echo(f"Issue Type: {itype.name} - {itype.id}")

    issue_dict = {
        'project': {'key': project},
        'summary': summary,
        'description': description,
        'issuetype': {'name': issuetype},
        'priority': {'name': priority},
    }

    if assignee:
        issue_dict['assignee'] = {'name': assignee}

    new_issue = jira.create_issue(fields=issue_dict)
    click.echo(f"Created ticket with ID: {new_issue.key}")


if __name__ == '__main__':
    main()
