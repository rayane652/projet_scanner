import socket

def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
            
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        return banner
    except:
        return ""
