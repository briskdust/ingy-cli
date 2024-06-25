"""
Contains utility functions for interacting with the MOBSF API
"""

import json
import os
import textwrap

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from tabulate import tabulate

SERVER = "http://127.0.0.1:8000"


def upload(x, apikey):
    """Upload File"""
    print(f"Uploading file {x}")
    if not os.path.exists(x):
        print(f"File {x} does not exist")
        return "File not found"
    with open(x, 'rb') as file:
        multipart_data = MultipartEncoder(fields={'file': (x, file, 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': apikey}
        response = requests.post(SERVER + '/api/v1/upload', data=multipart_data,
                             headers=headers, timeout=10)
        print(response.text)

        return response.text


def scan(data, apikey):
    """Scan the file"""
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': apikey}
    requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers, timeout=600)


def json_resp(data, apikey):
    """Generate JSON Report"""
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers, timeout=10)

    return response.text


def gen_pdf(data, apikey, output_location):
    """Generate PDF Report"""
    print("Generate PDF report")
    headers = {'Authorization': apikey}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/download_pdf',
                             data=data, headers=headers, stream=True, timeout=20)
    with open(output_location, 'wb') as flip:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                flip.write(chunk)
    print(f"Report saved to {output_location}")


def compare(hash1, hash2, apikey):
    """Compare two apk files"""
    headers = {'Authorization': apikey}
    data = {"hash1": hash1, "hash2": hash2}
    print("in comparison data is ", data)
    response = requests.post(SERVER + '/api/v1/compare', data=data, headers=headers, timeout=20)

    return response.text


def format_nested_dict(d, indent=0):
    """
    Recursively format nested dictionaries into a string
    with indented JSON-like format for better readability
    """
    items = []
    for key, value in d.items():
        if isinstance(value, dict):
            items.append(f"{' ' * indent}{key}:")
            items.append(format_nested_dict(value, indent + 4))
        elif isinstance(value, list) and all(isinstance(i, dict) for i in value):
            items.append(f"{' ' * indent}{key}: [{', '.
                         join(format_nested_dict(i, indent + 4) for i in value)}]")
        else:
            formatted_value = json.dumps(value, indent=indent + 4)\
                if isinstance(value, list) else value
            items.append(f"{' ' * indent}{key}: {formatted_value}")
    return "\n".join(items)


def gen_table(json_dict):
    """Generate a table from the JSON report data"""
    # Extracting top-level keys and values, formatting if values are complex
    check_list = []
    table_data = []
    crucial_keys = ["title", "file_name", "app_name", "size",
                    "exported_activities", "browsable_activities",
                    "providers", "version_name", "version_code",
                    "permissions", "malware_permissions",
                    "certificate_analysis", "manifest_analysis",
                    "network_security", "binary_analysis", "file_analysis",
                    "code_analysis", "niap_analysis", "permission_mapping",
                    "secrets", "average_cvss", "appsec",
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


def prettify_json(data):
    """Prettify JSON data for better readability"""
    json_dict = json.loads(data)

    # Extracting and organizing data into sections for presentation
    app_comparison = {
        "First App Version": json_dict["first_app"]["name_ver"],
        "Second App Version": json_dict["second_app"]["name_ver"],
        "First App Size": json_dict["first_app"]["size"],
        "Second App Size": json_dict["second_app"]["size"]
    }

    # Permissions detailed view
    common_permissions = [[perm[0], perm[1]['info']]
                          for perm in json_dict["permissions"]["common"]]
    only_first_permissions = [[perm[0], perm[1]['info']]
                              for perm in json_dict["permissions"]["only_first"]]
    only_second_permissions = [[perm[0], perm[1]['info']]
                               for perm in json_dict["permissions"]["only_second"]]

    # APIs used
    common_apis = [[api[0], ", ".join(api[1]['files'].keys())]
                   for api in json_dict["android_api"]["common"]]
    only_first_apis = [[api[0], ", ".join(api[1]['files'].keys())]
                       for api in json_dict["android_api"]["only_first"]]
    only_second_apis = [[api[0], ", ".join(api[1]['files'].keys())]
                        for api in json_dict["android_api"]["only_second"]]

    # Display basic info
    print("App Comparison:")
    print(tabulate(app_comparison.items(), headers=["Key", "Value"], tablefmt="grid"))

    # Display permissions
    print("\nCommon Permissions:")
    print(tabulate(common_permissions, headers=["Permission", "Info"], tablefmt="grid"))
    if only_first_permissions:
        print("\nPermissions Only in First App:")
        print(tabulate(only_first_permissions, headers=["Permission", "Info"], tablefmt="grid"))
    if only_second_permissions:
        print("\nPermissions Only in Second App:")
        print(tabulate(only_second_permissions, headers=["Permission", "Info"], tablefmt="grid"))

    # Display API usage
    print("\nAPI Usage (Common):")
    print(tabulate(common_apis, headers=["API Feature", "Files"], tablefmt="grid"))
    if only_first_apis:
        print("\nAPI Usage (Only First App):")
        print(tabulate(only_first_apis, headers=["API Feature", "Files"], tablefmt="grid"))
    if only_second_apis:
        print("\nAPI Usage (Only Second App):")
        print(tabulate(only_second_apis, headers=["API Feature", "Files"], tablefmt="grid"))


def remove_keys(data, keys):
    """Remove unnecessary keys from JSON data"""
    json_dict = json.loads(data)
    for key in keys:
        if key in json_dict:
            del json_dict[key]
    return json.dumps(json_dict)


def remove_non_security_related_keys(data):
    """Remove non-security related keys from the JSON data"""
    # Convert JSON string to dictionary
    data_dict = json.loads(data)

    # List of security-related keys to remove
    security_keys = [
        "version", "title", "file_name", "app_name",
        "size", "exported_activities", "browsable_activities",
        "providers", "version_name", "version_code",
        "permissions", "malware_permissions", "certificate_analysis",
        "manifest_analysis", "network_security", "binary_analysis",
        "file_analysis", "niap_analysis",
        "permission_mapping", "secrets", "average_cvss", "appsec",
        "trackers", "virus_total", "timestamp"
    ]

    # Iterate over the keys and remove them if they exist in the dictionary
    filtered_dict = {key: data_dict[key] for key in security_keys if key in data_dict}

    print(json.dumps(filtered_dict, indent=4))
    # Return the modified data as a JSON string
    return json.dumps(filtered_dict, indent=4)


def process_json(json_str):
    """Process JSON data and generate two lists of data"""
    data = json_str

    table_data = []

    # Define table headers
    headers = ["Severity", "Title", "Description", "Section"]
    severity_text = ""

    # Define a function to colorize text
    def colorize_text(text, color_code):
        return f"\033[{color_code}m{text}\033[0m"

    def wrap_section(text, width=60):
        return textwrap.TextWrapper(width=width, break_long_words=False, break_on_hyphens=True,
                                    replace_whitespace=False).fill(text)

    # Deal with each severity level
    for severity in ["high", "warning", "info", "secure"]:
        if severity in data:
            for item in data[severity]:
                if severity == "high":
                    severity_text = colorize_text("HIGH", "91")  # Red
                elif severity == "warning":
                    severity_text = colorize_text("WARNING", "93")  # Yellow
                elif severity == "info":
                    severity_text = colorize_text("INFO", "94")  # Blue
                elif severity == "secure":
                    severity_text = colorize_text("SECURE", "92")  # Green
                elif severity == "hotspot":
                    severity_text = colorize_text("HOTSPOT", "95")  # Magenta

                wrapped_title = wrap_section(item["title"])
                wrapped_description = wrap_section(item["description"])
                wrapped_section = wrap_section(item["section"])

                table_data.append([severity_text, wrapped_title,
                                   wrapped_description, wrapped_section])

    # Add additional information
    additional_info = [
        ["Security Score", colorize_score(data.get("security_score", "N/A"))],
        ["App Name", data.get("app_name", "N/A")],
        ["File Name", data.get("file_name", "N/A")],
        ["Hash", data.get("hash", "N/A")],
        ["Version", data.get("version_name", "N/A")],
        ["Total Trackers", data.get("total_trackers", "N/A")],
        ["Trackers", data.get("trackers", "N/A")],
    ]

    basic_info = tabulate(additional_info, headers=["Key", "Value"], tablefmt="fancy_grid")
    sec_info = tabulate(table_data, headers=headers, tablefmt="fancy_grid")

    return [basic_info, sec_info]


def process_response(response, apikey, pdf):
    """Process the response from the MOBSF API and display the results."""
    scan(response, apikey)

    if not pdf:
        new_rep_json = remove_non_security_related_keys(json_resp(response, apikey))
        j_dict = json.loads(new_rep_json)

        check_list, table_data = gen_table(j_dict)
        wrapped_data = [[item[0], wrap_text(item[1], width=150)] for item in table_data]
        check_lst = process_json(check_list)

        print(check_lst[0])
        print(check_lst[1])
        print(tabulate(wrapped_data, headers=["Key", "Value"], tablefmt="fancy_grid"))
    else:
        gen_pdf(response, apikey, pdf)


def compare_reports(responses, apikey):
    """Compare two reports from the MOBSF API and display the results."""
    hash1 = json.loads(responses[0])["hash"]
    hash2 = json.loads(responses[1])["hash"]
    comparison = compare(hash1, hash2, apikey)
    prettify_json(comparison)


def colorize_score(score):
    """Colorize the security score based on the value"""
    if score < 40:
        color = "\033[91m"  # Red
    elif 41 <= score <= 69:
        color = "\033[93m"  # Yellow
    else:
        color = "\033[92m"  # Green

    reset = "\033[0m"
    return f"{color}{score}{reset}"
