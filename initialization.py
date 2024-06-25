"""
Initializes the docker container for the Mobile Security Framework (MobSF) and runs it on port 8000.
"""

import subprocess


def init_mobsf():
    command_str = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"

    cmd = command_str.split(" ")
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def init_trivy():
    commands = [
        "sudo apt-get install -y wget apt-transport-https gnupg lsb-release",
        "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -",
        "echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list",
        "sudo apt-get update",
        "sudo apt-get install -y trivy"
    ]

    for command in commands:
        cmd = command.split(" ")
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
