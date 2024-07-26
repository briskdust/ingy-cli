"""
This script scans a repository for potential shell escape vulnerabilities
in Python, JavaScript, and Bash files.
"""

import os
import re
import sys
import subprocess

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# Define file extensions to check
FILE_EXTENSIONS = ['.py', '.sh', '.js']

# Define patterns to identify potential shell escape vulnerabilities
PATTERNS = {
    'subprocess_shell': re.compile(
        r'\bsubprocess\.run\(.+shell=True\b|\bsubprocess\.Popen\(.+shell=True\b'
    ),
    'os_system': re.compile(r'\bos\.system\(.+\)'),
    'eval': re.compile(r'\beval\(.+\)'),
    'exec': re.compile(r'\bexec\(.+\)'),
    'commands': re.compile(
        r'\bcommands\.getoutput\(.+\)|\bcommands\.getstatusoutput\(.+\)'
    ),
    # JavaScript patterns
    'child_process_exec': re.compile(r'\bexec\(.+\)'),
    'child_process_execFile': re.compile(r'\bexecFile\(.+\)'),
    'child_process_spawn': re.compile(r'\bspawn\(.+\)'),
    'child_process_fork': re.compile(r'\bfork\(.+\)')
}


def scan_file(file_path):
    """Scan a file for potential shell escape vulnerabilities."""
    if ".venv" in file_path:
        return []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()
    findings = []
    for line_num, line in enumerate(lines, 1):
        for vuln_name, pattern in PATTERNS.items():
            matches = pattern.findall(line)
            if matches:
                findings.append((vuln_name, line_num, matches))
    return findings


def scan_repo(repo_path):
    """Scan a repository for potential shell escape vulnerabilities."""
    vulnerabilities = {}
    for root, _, files in os.walk(repo_path):
        for file in files:
            if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                file_path = os.path.join(root, file)
                findings = scan_file(file_path)
                if findings:
                    vulnerabilities[file_path] = findings
    return vulnerabilities


def print_report(vulnerabilities):
    """Print the vulnerabilities found in the repository."""
    if not vulnerabilities:
        console.print("[green]No potential shell escape vulnerabilities found.[/green]")
        return

    for file_path, findings in vulnerabilities.items():
        table = Table(title=f"File: {file_path}", box=box.ROUNDED)
        table.add_column("Line", style="cyan", no_wrap=True)
        table.add_column("Vulnerability", style="magenta")
        table.add_column("Match", style="yellow")

        for vuln_name, line_num, matches in findings:
            for match in matches:
                table.add_row(str(line_num), vuln_name, match)

        console.print(table)
        console.print()  # Add a blank line between tables


def download_repo(repo_url, dest_path, seckey=None):
    """Clone a remote git repository to a destination path using an optional SSH key."""
    env = os.environ.copy()
    if seckey:
        env['GIT_SSH_COMMAND'] = f'ssh -i {seckey} -o IdentitiesOnly=yes'

    try:
        subprocess.run(['git', 'clone', repo_url, dest_path], check=True, env=env)
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        sys.exit(1)
