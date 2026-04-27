import socket


HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def grab_banner(ip, port):
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner

    except OSError:
        return ""

    finally:
        if sock:
            sock.close()
