import os
import subprocess

# Potential shell escape vulnerabilities
os.system("ls -l")
subprocess.Popen("ls -l", shell=True)
subprocess.run("ls -l", shell=True)
eval("print('Hello, world!')")
exec("print('Hello, world!')")
