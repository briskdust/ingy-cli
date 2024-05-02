"""
MOBSF REST API Python Requests
"""

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from tabulate import tabulate

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


json_data = """{"title": "Compare report", "version": "v3.9.8 Beta", "first_app": {"name_ver": "com.ingy - 2.0.5", "md5": "4862f7d84e28c14fed928d15f6ec65f0", "file_name": "Ingy-old.apk", "size": "7.4MB", "icon_path": "4862f7d84e28c14fed928d15f6ec65f0-icon.png", "activities": ["com.ingy.MainActivity", "com.ingy.IngyNfcManager"], "services": [], "providers": ["org.apache.cordova.camera.FileProvider", "nl.xservices.plugins.FileProvider"], "receivers": ["nl.xservices.plugins.ShareChooserPendingIntent"], "exported_count": {"exported_activities": 1, "exported_services": 0, "exported_receivers": 1, "exported_providers": 0}, "apkid": {"classes.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "anti_vm": ["Build.FINGERPRINT check", "Build.MODEL check", "Build.MANUFACTURER check"], "compiler": ["unknown (please file detection issue!)"]}, "classes10.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes11.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes2.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes3.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "anti_debug": ["Debug.isDebuggerConnected() check"], "compiler": ["unknown (please file detection issue!)"]}, "classes4.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes5.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes6.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes7.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes8.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}, "classes9.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "compiler": ["unknown (please file detection issue!)"]}}, "cert_subject": "Subject: CN=Android Debug, O=Android, C=US"}, "second_app": {"name_ver": "com.ingy - 2.0.6", "md5": "420790796f66b07d7a815085b075770d", "file_name": "Ingy.apk", "size": "10.43MB", "icon_path": "420790796f66b07d7a815085b075770d-icon.png", "activities": ["com.ingy.MainActivity", "com.ingy.IngyNfcManager"], "services": [], "providers": ["org.apache.cordova.camera.FileProvider", "nl.xservices.plugins.FileProvider", "androidx.startup.InitializationProvider"], "receivers": ["nl.xservices.plugins.ShareChooserPendingIntent"], "exported_count": {"exported_activities": 1, "exported_services": 0, "exported_receivers": 1, "exported_providers": 0}, "apkid": {"classes.dex": {"yara_issue": ["yara issue - dex file recognized by apkid but not yara module"], "anti_vm": ["Build.FINGERPRINT check", "Build.MANUFACTURER check"], "anti_debug": ["Debug.isDebuggerConnected() check"], "compiler": ["unknown (please file detection issue!)"]}}, "cert_subject": "Subject: C=US, ST=California, L=Mountain View, O=Google Inc., OU=Android, CN=Android"}, "urls": {"common": ["data:image/", "https://api.whatsapp.com/send?phone="], "only_first": [], "only_second": []}, "android_api": {"common": [["api_ipc", {"files": {"com/ingy/IngyNfcManager.java": "4,5,6,59,59,79,79,208,208,209,210,226,226,228,228,228,230,230,232", "com/ingy/MainActivity.java": "10", "com/ingy/sdk/IngyAndroidSdk.java": "4,109,109,109,110,117,284,284", "nl/xservices/plugins/ShareChooserPendingIntent.java": "5,7,11", "nl/xservices/plugins/SocialSharing.java": "3,7,9,87,93,96,99,107,112,114,124,127,133,140,140,141,144,149,149,190,191,191,196,196,198,198,198,198,199,199,199,225,228,229,232,274,274,274,275,275,275,275,276,276,276,276,277,287,295,297,301,304,310,316,318,321,330,336,337,341,363,363,365,365,365,365,365,367,367,367,368,368,368,370,400,400,404,563,563,585,591,593,596,638,638,640,640,659,674,674"}, "metadata": {"description": "Inter Process Communication", "severity": "info"}}], ["api_get_system_service", {"files": {"nl/xservices/plugins/SocialSharing.java": "384"}, "metadata": {"description": "Get System Service", "severity": "info"}}], ["api_start_activity", {"files": {"com/ingy/sdk/IngyAndroidSdk.java": "110,286", "nl/xservices/plugins/SocialSharing.java": "203,341,370,571,615"}, "metadata": {"description": "Starting Activity", "severity": "info"}}], ["api_local_file_io", {"files": {"com/ingy/IngyNfcManager.java": "12,13", "nl/xservices/plugins/SocialSharing.java": "216,22,23,23,24,24,25,25,26,26,27,179,288,689,726,727"}, "metadata": {"description": "Local File I/O Operations", "severity": "info"}}], ["api_clipboard", {"files": {"nl/xservices/plugins/SocialSharing.java": "5,5"}, "metadata": {"description": "Set or Read Clipboard data", "severity": "info"}}], ["api_base64_encode", {"files": {"nl/xservices/plugins/SocialSharing.java": "565,17"}, "metadata": {"description": "Base64 Encode", "severity": "info"}}], ["api_installed", {"files": {"nl/xservices/plugins/SocialSharing.java": "141,190,196,639,141"}, "metadata": {"description": "Get Installed Applications", "severity": "info"}}], ["api_crypto", {"files": {"com/ingy/sdk/IngyBleTransport.java": "195,32,33,34,35,36,37"}, "metadata": {"description": "Crypto", "severity": "info"}}]], "only_first": [], "only_second": []}, "permissions": {"common": [["android.permission.INTERNET", {"status": "normal", "info": "full Internet access", "description": "Allows an application to create network sockets."}], ["android.permission.BLUETOOTH", {"status": "normal", "info": "create Bluetooth connections", "description": "Allows applications to connect to paired bluetooth devices."}], ["android.permission.BLUETOOTH_ADMIN", {"status": "normal", "info": "bluetooth administration", "description": "Allows applications to discover and pair bluetooth devices."}], ["android.permission.ACCESS_FINE_LOCATION", {"status": "dangerous", "info": "fine (GPS) location", "description": "Access fine location sources, such as the Global Positioning System on the phone, where available. Malicious applications can use this to determine where you are and may consume additional battery power."}], ["android.permission.NFC", {"status": "normal", "info": "control Near-Field Communication", "description": "Allows an application to communicate with Near-Field Communication (NFC) tags, cards and readers."}], ["android.permission.WRITE_EXTERNAL_STORAGE", {"status": "dangerous", "info": "read/modify/delete external storage contents", "description": "Allows an application to write to external storage."}], ["android.permission.ACCESS_NETWORK_STATE", {"status": "normal", "info": "view network status", "description": "Allows an application to view the status of all networks."}]], "only_first": [], "only_second": [["android.permission.ACCESS_COARSE_LOCATION", {"status": "dangerous", "info": "coarse (network-based) location", "description": "Access coarse location sources, such as the mobile network database, to determine an approximate phone location, where available. Malicious applications can use this to determine approximately where you are."}], ["android.permission.BLUETOOTH_SCAN", {"status": "dangerous", "info": "required for discovering and pairing Bluetooth devices.", "description": "Required to be able to discover and pair nearby Bluetooth devices."}], ["android.permission.BLUETOOTH_ADVERTISE", {"status": "dangerous", "info": "required to advertise to nearby Bluetooth devices.", "description": "Required to be able to advertise to nearby Bluetooth devices."}], ["android.permission.BLUETOOTH_CONNECT", {"status": "dangerous", "info": "necessary for connecting to paired Bluetooth devices.", "description": "Required to be able to connect to paired Bluetooth devices."}], ["android.permission.READ_MEDIA_IMAGES", {"status": "dangerous", "info": "allows reading image files from external storage.", "description": "Allows an application to read image files from external storage."}], ["android.permission.READ_MEDIA_VIDEO", {"status": "dangerous", "info": "allows reading video files from external storage.", "description": "Allows an application to read video files from external storage."}], ["com.ingy.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION", {"status": "unknown", "info": "Unknown permission", "description": "Unknown permission from android reference"}]]}, "browsable_activities": {"common": [], "only_first": [], "only_second": []}, "common_browsable_activities": {}, "apkid": {"common": {"anti_vm": ["Build.MANUFACTURER check", "Build.FINGERPRINT check"], "compiler": ["unknown (please file detection issue!)"], "obfuscator": [], "packer": [], "dropper": [], "manipulator": [], "anti_disassembly": [], "anti_debug": ["Debug.isDebuggerConnected() check"], "abnormal": []}, "only_first": {"anti_vm": ["Build.MODEL check"], "compiler": [], "obfuscator": [], "packer": [], "dropper": [], "manipulator": [], "anti_disassembly": [], "anti_debug": [], "abnormal": []}, "only_second": {"anti_vm": [], "compiler": [], "obfuscator": [], "packer": [], "dropper": [], "manipulator": [], "anti_disassembly": [], "anti_debug": [], "abnormal": []}}, "apkid_error": false}
"""


def prettify_json(data):
    json_dict = json.loads(data)

    # Extracting and organizing data into sections for presentation
    app_comparison = {
        "First App Version": json_dict["first_app"]["name_ver"],
        "Second App Version": json_dict["second_app"]["name_ver"],
        "First App Size": json_dict["first_app"]["size"],
        "Second App Size": json_dict["second_app"]["size"]
    }

    # Permissions detailed view
    common_permissions = [[perm[0], perm[1]['info']] for perm in json_dict["permissions"]["common"]]
    only_first_permissions = [[perm[0], perm[1]['info']] for perm in json_dict["permissions"]["only_first"]]
    only_second_permissions = [[perm[0], perm[1]['info']] for perm in json_dict["permissions"]["only_second"]]

    # APIs used
    common_apis = [[api[0], ", ".join(api[1]['files'].keys())] for api in json_dict["android_api"]["common"]]
    only_first_apis = [[api[0], ", ".join(api[1]['files'].keys())] for api in json_dict["android_api"]["only_first"]]
    only_second_apis = [[api[0], ", ".join(api[1]['files'].keys())] for api in json_dict["android_api"]["only_second"]]

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


# Run the function with the provided JSON data
# prettify_json(json_data)


def remove_keys(data, keys):
    json_dict = json.loads(data)
    for key in keys:
        if key in json_dict:
            del json_dict[key]
    return json.dumps(json_dict)


def remove_non_security_related_keys(data):
    # Convert JSON string to dictionary
    data_dict = json.loads(data)

    # List of security-related keys to remove
    security_keys = [
        "version", "title", "file_name", "app_name", "size", "exported_activities", "browsable_activities",
        "providers", "version_name", "version_code",
        "permissions", "malware_permissions", "certificate_analysis",
        "manifest_analysis", "network_security", "binary_analysis", "file_analysis", "code_analysis", "niap_analysis",
        "permission_mapping", "secrets", "average_cvss", "appsec",
        "trackers", "virus_total", "timestamp"
    ]

    # Iterate over the keys and remove them if they exist in the dictionary
    filtered_dict = {key: data_dict[key] for key in security_keys if key in data_dict}

    # Return the modified data as a JSON string
    return json.dumps(filtered_dict, indent=4)
