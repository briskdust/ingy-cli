from boofuzz import (
    Session,
    Target,
    SocketConnection,
    s_initialize,
    s_block,
    s_string,
    s_delim,
    s_static,
    s_size,
    s_get
)


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.233", 8080, proto='tcp')
        )
    )

    endpoints = [
        ("/authenticate", {"username": "admin", "password": "password123"}),
        ("/resetPassword", {"passwordResetCode": "123456"}),
        ("/setGatewayNetwork", {"networkAddress": "192.168.1.1", "cipherKey": "key", "authKey": "auth"}),
        ("/setGatewayLock", {"shouldLock": True, "siteId": "site123", "siteKey": "key123"}),
        ("/runOtap", {"otapFile": "filecontent", "disableWhenDone": True, "force": True}),
        ("/checkOtap", {"otapFile": "filecontent"})
    ]

    for endpoint, body in endpoints:
        s_initialize(name=endpoint)
        with s_block("Request-Header"):
            s_string("POST", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string(endpoint, fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("HTTP/1.1", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_string("Host:", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("192.168.1.233", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_string("User-Agent:", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("boofuzz", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_string("Content-Type:", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("application/json", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_static("\r\n")

        if body is not None:
            with s_block("Request-Body"):
                s_string("{", fuzzable=False)
                for i, (key, value) in enumerate(body.items()):
                    if i > 0:
                        s_string(',', fuzzable=False)
                    s_string(f'"{key}":', fuzzable=False)
                    if isinstance(value, str):
                        s_string(f'"{value}"', name=key, fuzzable=True)
                    else:
                        s_string(f'{value}', name=key, fuzzable=True)
                s_string("}", fuzzable=False)
            s_static("Content-Length: ")
            s_size("Request-Body", output_format="ascii", fuzzable=False)
            s_static("\r\n\r\n")
        else:
            s_static("\r\n")

        session.connect(s_get(endpoint))

    get_endpoints = [
        "/forceRestartDocker",
        "/passwordResetChallengeCode",
        "/backupSiteResult",
        "/exportInfluxDb"
    ]

    for endpoint in get_endpoints:
        s_initialize(name=endpoint)
        with s_block("Request-Header"):
            s_string("GET", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string(endpoint, fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("HTTP/1.1", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_string("Host:", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("192.168.1.233", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_string("User-Agent:", fuzzable=False)
            s_delim(" ", fuzzable=False)
            s_string("boofuzz", fuzzable=False)
            s_delim("\r\n", fuzzable=False)
            s_static("\r\n")

        session.connect(s_get(endpoint))

    session.fuzz()


if __name__ == "__main__":
    main()
