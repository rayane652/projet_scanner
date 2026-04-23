import requests

def scan_website(url):
    data = {}

    try:
        response = requests.get(url, timeout=3)

        data["status_code"] = response.status_code
        data["headers"] = dict(response.headers)

        # basic tech hints
        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")

        data["server"] = server
        data["powered_by"] = powered

    except Exception as e:
        data["error"] = str(e)

    return data
