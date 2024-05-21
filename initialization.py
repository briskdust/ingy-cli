"""
Initializes the docker container for the Mobile Security Framework (MobSF) and runs it on port 8000.
"""

import subprocess

COMMAND_STR = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"

cmd = COMMAND_STR.split(" ")
subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
