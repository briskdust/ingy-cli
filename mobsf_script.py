import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from utils import remove_non_security_related_keys, prettify_json
from tabulate import tabulate
import click
import textwrap


SERVER = "http://127.0.0.1:8000"


@click.command()
@click.argument('files', nargs=-1)
@click.option('--apikey', envvar='MOBSF_APIKEY', prompt=True, help='API key for authentication')
def main(files, apikey):
    if not files:
        file1 = click.prompt("Enter the file path")
        file2 = click.prompt("Enter the file path of another apk package, enter \"n\" to skip")
        if file2 != "n":
            files = [file1, file2]
        else:
            files = [file1]
    """Process files and generate reports."""
    responses = [upload(file, apikey) for file in files]

    rep_json = json_resp(responses[0], apikey)
    new_rep_json = remove_non_security_related_keys(rep_json)
    j_dict = json.loads(new_rep_json)

    table_data = gen_table(j_dict)
    wrapped_data = [[item[0], wrap_text(item[1], width=200)] for item in table_data]
    print(tabulate(wrapped_data, headers=["Key", "Value"], tablefmt="grid"))

    if len(files) == 2:
        rep_json_2 = json_resp(responses[1], apikey)
        new_rep_json_2 = remove_non_security_related_keys(rep_json_2)
        j_dict_2 = json.loads(new_rep_json_2)
        table_data_2 = gen_table(j_dict_2)
        wrapped_data_2 = [[item[0], wrap_text(item[1], width=200)] for item in table_data_2]
        print(tabulate(wrapped_data_2, headers=["Key", "Value"], tablefmt="grid"))

        hash1 = json.loads(responses[0])["hash"]
        hash2 = json.loads(responses[1])["hash"]
        comparison = compare(hash1, hash2, apikey)
        prettify_json(comparison)


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
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    print(response.text)


def json_resp(data, apikey):
    """Generate JSON Report"""
    print("Generate JSON report")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)
    # print(response.text)
    return response.text


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
    for key, value in json_dict.items():
        if isinstance(value, dict):
            formatted_value = format_nested_dict(value)
        elif isinstance(value, list):
            formatted_value = json.dumps(value, indent=4)
        else:
            formatted_value = value
        table_data.append([key, formatted_value])

    return table_data


def wrap_text(text, width=120):
    """Wrap text to the specified width using textwrap library, handling None values and preserving original new lines."""
    if text is None:
        return None

    wrapped_lines = [textwrap.fill(part, width) for part in text.split('\n')]
    return '\n'.join(wrapped_lines)


if __name__ == '__main__':
    main()
