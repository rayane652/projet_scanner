import requests

def scan_website(url):
    data = {}

    try:
        response = requests.get(url, timeout=3)

        data["status_code"] = response.status_code
        data["headers"] = dict(response.headers)

        # simple tech hints
        data["server"] = response.headers.get("Server", "")
        data["powered_by"] = response.headers.get("X-Powered-By", "")

    except Exception as e:
        data["error"] = str(e)

    return data