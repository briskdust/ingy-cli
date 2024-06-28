"""
Initializes the docker container for the Mobile Security Framework (MobSF) and runs it on port 8000.
"""
import os
import subprocess


def init_mobsf():
    """
    Initializes the docker container for the Mobile Security Framework (MobSF)
    and runs it on port 8000.
    """
    command_str = "docker run -it --rm -p 8000:8000\
     opensecurity/mobile-security-framework-mobsf:latest"
    os.system(command_str)


def install_trivy():
    """Installs Trivy for scanning Docker images for security vulnerabilities."""
    commands = [
        "sudo apt-get install -y wget apt-transport-https gnupg lsb-release",
        "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -",
        "echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main |\
         sudo tee -a /etc/apt/sources.list.d/trivy.list",
        "sudo apt-get update",
        "sudo apt-get install -y trivy"
    ]

    for command in commands:
        cmd = command.split(" ")
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def install_bandit():
    """Install Bandit for scanning Python code for security vulnerabilities."""
    subprocess.run(['pip', 'install', 'bandit'], check=True)
