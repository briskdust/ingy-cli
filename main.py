from flask import Flask, request, jsonify
import subprocess

from flask_cors import CORS

from utils import *

app = Flask(__name__)
CORS(app)


@app.route('/trivy', methods=['GET'])
def run_trivy_scan():
    image_name = request.args.get('name')
    if not image_name:
        return jsonify({"error": "Missing 'name' parameter"}), 400

    trimmed_name = image_name.split("/")[-1]

    # Define the Trivy command
    output_file = f"/Users/briskdust/{trimmed_name}.html"
    template_path = "/Users/briskdust/html.tpl"
    cmd = [
        "trivy", "image",
        "--format", "template",
        "--template", f"@{template_path}",
        "-o", output_file,
        image_name
    ]

    # Execute the Trivy command
    try:
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jsonify({"message": "Scan completed successfully", "output": output_file}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Trivy scan failed", "details": str(e)}), 500


@app.route('/trial', methods=['GET'])
def run_trial():
    name1 = request.args.get('apikey')
    print(name1)
    return jsonify({"message": "Scan completed successfully", "output": name1}), 200


@app.route('/mobsf', methods=['GET'])
def run_mobsf_scan():
    api_key = request.args.get('apikey')
    filename = request.args.get('filename')
    output_location = request.args.get('output')

    print(api_key)
    print(filename)

    response = upload(filename, api_key)
    scan(response, api_key)

    pdf(response, api_key, output_location)

    return jsonify({"message": "Scan completed successfully", "output": filename}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5050)
