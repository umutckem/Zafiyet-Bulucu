import requests

def opencve_search(vendor, page=1):
    try:
        url = f"https://app.opencve.io/api/cve?vendor={vendor}&page={page}"
        headers = {
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json().get("results", [])
        else:
            print(f"❗ OpenCVE API Hatası: {response.status_code}")
            return []
    except Exception as e:
        print(f"❗ OpenCVE bağlantı hatası: {e}")
        return []

def opencve_search_by_cveid(cve_id):
    try:
        url = f"https://app.opencve.io/api/cve/{cve_id}"
        headers = {
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print(f"❗ OpenCVE bağlantı hatası: {e}")
        return None
