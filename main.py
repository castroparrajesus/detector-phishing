from analyzer import analizar
from apis import verificar_todas

def barra(score):
    lleno = score // 5
    return "[" + "#" * lleno + "-" * (20 - lleno) + "] " + str(score) + "/100"

def mostrar(r, apis):
    print()
    print("  URL:     ", r["url"])
    print("  Dominio: ", r["dominio"])
    print("  Nivel:   ", r["nivel"])
    print("  Riesgo:  ", barra(r["score"]))
    print("  HTTPS:   ", "Si" if r["usa_https"] else "No")
    print()

    if r["señales"]:
        print("  Señales detectadas:")
        for s in r["señales"]:
            print(f"    !! {s}")
    else:
        print("  No se detectaron señales sospechosas.")

    print()
    print("  Verificacion en bases de datos:")

    vt = apis["virustotal"]
    if not vt["disponible"]:
        print(f"    VirusTotal:      No disponible ({vt['razon']})")
    elif vt["limpia"]:
        print(f"    VirusTotal:      Limpia (0/{vt['total']} motores la marcaron)")
    else:
        print(f"    VirusTotal:      DETECTADA — {vt['maliciosas']} maliciosa(s), {vt['sospechosas']} sospechosa(s)")

    sb = apis["safebrowsing"]
    if not sb["disponible"]:
        print(f"    Google SafeBrow: No disponible ({sb['razon']})")
    elif not sb["peligrosa"]:
        print(f"    Google SafeBrow: No encontrada en listas negras")
    else:
        print(f"    Google SafeBrow: PELIGROSA — {', '.join(sb['amenazas'])}")
    print()

print()
print("  === Detector de Phishing ===")
print()

url = input("  Pega la URL a analizar: ").strip()
print()
print("  Analizando...")

resultado = analizar(url)
print("  Consultando bases de datos...")
apis = verificar_todas(url)
mostrar(resultado, apis)