import subprocess

command_str = "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"

cmd = command_str.split(" ")
subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
