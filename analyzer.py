import re
from urllib.parse import urlparse

# Marcas legítimas que los phishers imitan frecuentemente
MARCAS_OBJETIVO = [
    "paypal", "google", "facebook", "apple", "microsoft", "amazon",
    "netflix", "instagram", "twitter", "whatsapp", "bancolombia",
    "davivienda", "bbva", "nequi", "rappi", "mercadolibre"
]

# Dominios de confianza conocidos
DOMINIOS_LEGÍTIMOS = {
    "google.com", "gmail.com", "youtube.com",
    "facebook.com", "instagram.com", "twitter.com",
    "apple.com", "icloud.com", "microsoft.com",
    "amazon.com", "netflix.com", "paypal.com",
    "bancolombia.com", "davivienda.com", "bbva.com.co",
    "nequi.com.co", "rappi.com", "mercadolibre.com"
}

# Palabras clave frecuentes en phishing
PALABRAS_PHISHING = [
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "confirm", "account", "banking", "password", "credential",
    "suspend", "urgent", "alert", "validate", "authentication",
    "acceso", "verificar", "confirmar", "seguro", "cuenta", "clave",
    "contrasena", "actualizar", "suspendido", "urgente", "banco"
]

# Extensiones de dominio sospechosas
TLDS_SOSPECHOSOS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".online", ".site", ".web", ".info", ".biz"
]

def extraer_dominio(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        return urlparse(url).netloc.lower()
    except:
        return ""

def extraer_ruta(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        return (parsed.path + "?" + parsed.query).lower()
    except:
        return ""

def analizar(url: str) -> dict:
    url_lower = url.lower().strip()
    dominio = extraer_dominio(url)
    ruta = extraer_ruta(url)
    url_completa = url_lower

    señales = []
    score = 0  # 0 = seguro, sube con cada señal sospechosa

    # 1. Usa IP en vez de dominio
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        señales.append("Usa dirección IP en vez de dominio")
        score += 30

    # 2. Dominio muy largo (más de 30 caracteres)
    dominio_sin_www = dominio.replace("www.", "")
    if len(dominio_sin_www) > 30:
        señales.append(f"Dominio sospechosamente largo ({len(dominio_sin_www)} caracteres)")
        score += 15

    # 3. Muchos subdominios (más de 3 puntos)
    if dominio.count(".") > 3:
        señales.append("Tiene demasiados subdominios")
        score += 20

    # 4. Marca legítima en subdominio (ej: paypal.sitemaligno.com)
    partes = dominio.split(".")
    dominio_raiz = ".".join(partes[-2:]) if len(partes) >= 2 else dominio
    for marca in MARCAS_OBJETIVO:
        if marca in dominio and dominio_raiz not in DOMINIOS_LEGÍTIMOS:
            señales.append(f"Imita la marca '{marca}' pero no es el dominio oficial")
            score += 40
            break

    # 5. Marca legítima en la ruta (ej: sitemaligno.com/paypal/login)
    for marca in MARCAS_OBJETIVO:
        if marca in ruta:
            señales.append(f"Menciona '{marca}' en la ruta de la URL")
            score += 20
            break

    # 6. Palabras clave de phishing en la URL
    encontradas = [p for p in PALABRAS_PHISHING if p in url_completa]
    if encontradas:
        señales.append(f"Contiene palabras de phishing: {', '.join(encontradas[:3])}")
        score += len(encontradas) * 8

    # 7. Guiones excesivos en el dominio
    if dominio.count("-") >= 3:
        señales.append("El dominio tiene muchos guiones (técnica de ofuscación)")
        score += 15

    # 8. TLD sospechoso
    for tld in TLDS_SOSPECHOSOS:
        if dominio.endswith(tld):
            señales.append(f"Usa un dominio de alto riesgo: '{tld}'")
            score += 20
            break

    # 9. URL muy larga (más de 100 caracteres)
    if len(url) > 100:
        señales.append(f"URL sospechosamente larga ({len(url)} caracteres)")
        score += 10

    # 10. Usa HTTPS (reduce sospecha pero no garantiza nada)
    usa_https = url_lower.startswith("https")
    if not usa_https:
        señales.append("No usa HTTPS — la conexión no está cifrada")
        score += 15

    # 11. Typosquatting — dominios parecidos a marcas (ej: paypa1, gooogle)
    for marca in MARCAS_OBJETIVO:
        if marca not in dominio_raiz and _similitud(marca, dominio_raiz.split(".")[0]) > 0.8:
            señales.append(f"El dominio es muy similar a '{marca}' (posible typosquatting)")
            score += 35
            break

    score = min(100, score)

    if score == 0:      nivel = "SEGURO"
    elif score < 30:    nivel = "BAJO RIESGO"
    elif score < 60:    nivel = "SOSPECHOSO"
    else:               nivel = "PELIGROSO"

    return {
        "url":       url,
        "dominio":   dominio,
        "score":     score,
        "nivel":     nivel,
        "señales":   señales,
        "usa_https": usa_https,
    }

def _similitud(a: str, b: str) -> float:
    """Calcula similitud entre dos strings (0 a 1)"""
    if not a or not b:
        return 0
    a, b = a.lower(), b.lower()
    if a == b:
        return 1.0
    matches = sum(1 for c in a if c in b)
    return matches / max(len(a), len(b))