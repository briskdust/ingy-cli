"""Boofuzz script to fuzz the login page of the gateway configuration dashboard."""

from boofuzz import (Session, Target, SocketConnection, s_initialize, s_block, s_string, s_delim,
                     s_group, s_size, s_static, s_get)


def main():
    # Target configuration
    session = Session(
        target=Target(
            connection=SocketConnection("192.168.1.233", 8080, proto='tcp')
        )
    )

    # Initialize fuzzing session
    s_initialize(name="User Login")

    # Construct the HTTP POST request
    with s_block("Request-Header"):
        s_string("POST", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("/login", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("HTTP/1.1", fuzzable=False)
        s_delim("\r\n", fuzzable=False)
        s_string("Host:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("192.168.1.233")
        s_delim("\r\n", fuzzable=False)
        s_string("User-Agent:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("boofuzz")
        s_delim("\r\n", fuzzable=False)
        s_string("Content-Type:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("application/x-www-form-urlencoded")
        s_delim("\r\n", fuzzable=False)

    # Using dictionary for fuzzing username and password
    with s_block("Request-Body"):
        s_string("username=", fuzzable=False)
        s_group("username", values=["admin", "user", "test", "guest", "root"])
        s_delim("&", fuzzable=False)
        s_string("password=", fuzzable=False)
        s_group("password", values=["password", "123456", "admin", "password1", "root"])

    # Calculate Content-Length and set the header
    s_static("\r\nContent-Length: ")
    s_size("Request-Body", output_format="ascii", fuzzable=False)
    s_static("\r\n\r\n")

    # Connect and start fuzzing
    session.connect(s_get("User Login"))
    session.fuzz()


if __name__ == "__main__":
    main()
