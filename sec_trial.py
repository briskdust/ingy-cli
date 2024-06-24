import os
import subprocess


def run_bandit(path):
    """Run Bandit to check Python code for shell escape vulnerabilities."""
    result = subprocess.run(['bandit', '-r', path, '-f', 'json'], capture_output=True, text=True)
    print("Bandit output:")
    print(result.stdout)


def run_eslint(path):
    """Run ESLint to check JavaScript code for shell escape vulnerabilities."""
    result = subprocess.run(['eslint', path], capture_output=True, text=True)
    print("ESLint output:")
    print(result.stdout)


def scan_directory(path):
    """Scan directory for potential shell escape vulnerabilities."""
    for root, dirs, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith('.py'):
                pass
                # print(f"Running Bandit on {full_path}")
                # run_bandit(full_path)
            elif file.endswith('.js'):
                print(f"Running ESLint on {full_path}")
                run_eslint(full_path)


if __name__ == "__main__":
    repo_path = input("Enter the path to the repository: ")
    if not os.path.isdir(repo_path):
        print(f"The provided path is not a directory: {repo_path}")
    else:
        scan_directory(repo_path)
