import requests
import base64

import os
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

def verificar_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {"disponible": False, "razon": "API key no configurada"}

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            return {"disponible": True, "maliciosas": 0, "sospechosas": 0, "total": 0, "limpia": True}

        if response.status_code != 200:
            return {"disponible": False, "razon": f"Error {response.status_code}"}

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        maliciosas  = stats.get("malicious", 0)
        sospechosas = stats.get("suspicious", 0)
        total       = sum(stats.values())

        return {
            "disponible":  True,
            "maliciosas":  maliciosas,
            "sospechosas": sospechosas,
            "total":       total,
            "limpia":      maliciosas == 0 and sospechosas == 0,
        }
    except requests.exceptions.ConnectionError:
        return {"disponible": False, "razon": "Sin conexion"}
    except Exception as e:
        return {"disponible": False, "razon": str(e)}

def verificar_google_safebrowsing(url):
    return {"disponible": False, "razon": "API key no configurada"}

def verificar_todas(url):
    return {
        "virustotal":   verificar_virustotal(url),
        "safebrowsing": verificar_google_safebrowsing(url),
    }