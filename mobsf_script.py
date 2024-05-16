import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import subprocess
from utils import remove_non_security_related_keys, prettify_json, process_json
from tabulate import tabulate
import click
import textwrap

SERVER = "http://127.0.0.1:8000"


@click.group()
def main():
    pass


@main.group()
def cloud():
    pass


@main.group()
def mobile():
    pass


@main.group()
def gateway():
    pass


# ------------------------------- MOBSF Command -------------------------------
@mobile.command()
@click.argument('files', nargs=-1)
@click.option('--apikey', envvar='MOBSF_APIKEY', prompt=True, help='API key for authentication')
@click.option('--pdf', help='Generate PDF report')
def mobsf(files, apikey, pdf):
    """Scan and analyze APK files for security vulnerabilities using MobSF."""
    if not files:
        file1 = click.prompt("Enter the file path")
        file2 = click.prompt("Enter the file path of another apk package, enter \"n\" to skip")
        if file2 != "n":
            files = [file1, file2]
        else:
            files = [file1]
    """Process files and generate reports."""
    responses = [upload(file, apikey) for file in files]

    scan(responses[0], apikey)

    if not pdf:
        rep_json = json_resp(responses[0], apikey)
        new_rep_json = remove_non_security_related_keys(rep_json)
        j_dict = json.loads(new_rep_json)

        check_list, table_data = gen_table(j_dict)
        wrapped_data = [[item[0], wrap_text(item[1], width=150)] for item in table_data]
        check_lst = process_json(check_list)
        print(check_lst[0])
        print(check_lst[1])
        print(tabulate(wrapped_data, headers=["Key", "Value"], tablefmt="grid"))
    else:
        gen_pdf(responses[0], apikey, pdf)

    if len(files) == 2:
        scan(responses[1], apikey)
        if not pdf:
            rep_json_2 = json_resp(responses[1], apikey)
            new_rep_json_2 = remove_non_security_related_keys(rep_json_2)
            j_dict_2 = json.loads(new_rep_json_2)
            check_list_2, table_data_2 = gen_table(j_dict_2)
            check_lst_2 = process_json(check_list_2)
            print(check_lst_2[0])
            print(check_lst_2[1])
            wrapped_data_2 = [[item[0], wrap_text(item[1], width=150)] for item in table_data_2]
            print(tabulate(wrapped_data_2, headers=["Key", "Value"], tablefmt="grid"))

            hash1 = json.loads(responses[0])["hash"]
            hash2 = json.loads(responses[1])["hash"]
            comparison = compare(hash1, hash2, apikey)
            prettify_json(comparison)

        if pdf:
            gen_pdf(responses[1], apikey, pdf)


# ------------------------------- Cloud Command -------------------------------
@cloud.command()
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


# ------------------------------- utils -------------------------------
def upload(x, apikey):
    """Upload File"""
    print(f"Uploading file {x}")
    multipart_data = MultipartEncoder(fields={'file': (x, open(x, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': apikey}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    print(response.text)

    return response.text


def scan(data, apikey):
    """Scan the file"""
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': apikey}
    requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)


def json_resp(data, apikey):
    """Generate JSON Report"""
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)

    return response.text


def gen_pdf(data, apikey, output_location):
    """Generate PDF Report"""
    print("Generate PDF report")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
    with open(output_location, 'wb') as flip:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                flip.write(chunk)
    print(f"Report saved to {output_location}")


def compare(hash1, hash2, apikey):
    headers = {'Authorization': apikey}
    data = {"hash1": hash1, "hash2": hash2}
    print("in comparinsg data is ", data)
    response = requests.post(SERVER + '/api/v1/compare', data=data, headers=headers)

    return response.text


def format_nested_dict(d, indent=0):
    """ Recursively format nested dictionaries into a string with indented JSON-like format for better readability """
    items = []
    for key, value in d.items():
        if isinstance(value, dict):
            items.append(f"{' ' * indent}{key}:")
            items.append(format_nested_dict(value, indent + 4))
        elif isinstance(value, list) and all(isinstance(i, dict) for i in value):
            items.append(f"{' ' * indent}{key}: [{', '.join(format_nested_dict(i, indent + 4) for i in value)}]")
        else:
            formatted_value = json.dumps(value, indent=indent + 4) if isinstance(value, list) else value
            items.append(f"{' ' * indent}{key}: {formatted_value}")
    return "\n".join(items)


def gen_table(json_dict):
    # Extracting top-level keys and values, formatting if values are complex
    table_data = []
    crucial_keys = ["title", "file_name", "app_name", "size", "exported_activities", "browsable_activities",
                    "providers", "version_name", "version_code", "permissions", "malware_permissions",
                    "certificate_analysis", "manifest_analysis", "network_security", "binary_analysis", "file_analysis",
                    "code_analysis", "niap_analysis", "permission_mapping", "secrets", "average_cvss", "appsec",
                    "trackers", "virus_total", "timestamp"]
    for key, value in json_dict.items():
        if key not in crucial_keys:
            continue
        if key == "appsec":
            check_list = value
            continue
        if isinstance(value, dict):
            formatted_value = format_nested_dict(value)
        elif isinstance(value, list):
            formatted_value = json.dumps(value, indent=4)
        else:
            formatted_value = value
        table_data.append([key, formatted_value])

    return check_list, table_data


def wrap_text(text, width=120):
    """
    Wrap text to the specified width using textwrap library,
    handling None values and preserving original new lines.
    """
    if text is None:
        return None

    wrapped_lines = [textwrap.fill(part, width) for part in text.split('\n')]
    return '\n'.join(wrapped_lines)


if __name__ == '__main__':
    main()
