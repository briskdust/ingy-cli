"""
MOBSF REST API Python Requests
"""

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"

FILE1 = 'Ingy.apk'
APIKEY = "d55fdfbd2721715bc6e936e634de823976bcb2a647a69331d1b5eed68ab7bbec"


def upload(x, api_key):
    """Upload File"""
    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (x, open(x, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': api_key}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    print(response.text)
    return response.text


def scan(data, api_key):
    """Scan the file"""
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': api_key}
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    print(response.text)


def pdf(data, api_key, output_location):
    """Generate PDF Report"""
    print("Generate PDF report")
    headers = {'Authorization': api_key}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
    with open(output_location, 'wb') as flip:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                flip.write(chunk)
    print("Report saved as report.pdf")
