import tkinter as tk
from tkinter import font
from analyzer import analizar
from apis import verificar_todas
import threading

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Detector de Phishing")
        self.root.geometry("520x580")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f5f5")
        self.construir()

    def construir(self):
        tk.Label(self.root, text="Detector de Phishing",
                 font=("Segoe UI", 16, "bold"),
                 bg="#f5f5f5", fg="#1a1a1a").pack(pady=(28, 4))

        tk.Label(self.root, text="Pega una URL para analizarla",
                 font=("Segoe UI", 10),
                 bg="#f5f5f5", fg="#888").pack(pady=(0, 20))

        # Campo URL
        frame_url = tk.Frame(self.root, bg="#f5f5f5")
        frame_url.pack(padx=36, fill="x")

        self.entrada = tk.Entry(frame_url, font=("Segoe UI", 12),
                                relief="flat", bd=0, bg="white",
                                fg="#1a1a1a", insertbackground="#1a1a1a")
        self.entrada.pack(side="left", fill="x", expand=True,
                          ipady=10, ipadx=12)

        tk.Frame(self.root, height=2, bg="#e0e0e0").pack(
            padx=36, fill="x", pady=(0, 16))

        # Barra de riesgo
        tk.Label(self.root, text="Nivel de riesgo",
                 font=("Segoe UI", 9), bg="#f5f5f5",
                 fg="#aaa").pack(anchor="w", padx=36)

        self.canvas_barra = tk.Canvas(self.root, height=10,
                                       bg="#f5f5f5", highlightthickness=0)
        self.canvas_barra.pack(padx=36, fill="x", pady=(4, 2))

        self.lbl_nivel = tk.Label(self.root, text="—",
                                   font=("Segoe UI", 13, "bold"),
                                   bg="#f5f5f5", fg="#aaa")
        self.lbl_nivel.pack(anchor="w", padx=36, pady=(4, 14))

        # Métricas
        frame_met = tk.Frame(self.root, bg="#f5f5f5")
        frame_met.pack(padx=36, fill="x", pady=(0, 16))

        self.lbl_dominio  = self.metrica(frame_met, "Dominio", "—", 0)
        self.lbl_https    = self.metrica(frame_met, "HTTPS", "—", 1)
        self.lbl_score    = self.metrica(frame_met, "Score", "—", 2)

        # Señales
        tk.Label(self.root, text="Señales detectadas",
                 font=("Segoe UI", 9), bg="#f5f5f5",
                 fg="#aaa").pack(anchor="w", padx=36)

        self.frame_señales = tk.Frame(self.root, bg="#f5f5f5")
        self.frame_señales.pack(padx=36, fill="x", pady=(6, 12))

        self.lbl_señales = tk.Label(self.frame_señales,
                                     text="Ingresa una URL para analizar",
                                     font=("Segoe UI", 10),
                                     bg="#f5f5f5", fg="#bbb",
                                     wraplength=440, justify="left")
        self.lbl_señales.pack(anchor="w")

        # VirusTotal
        self.lbl_vt = tk.Label(self.root, text="",
                                font=("Segoe UI", 10),
                                bg="#f5f5f5", fg="#888",
                                wraplength=440, justify="left")
        self.lbl_vt.pack(anchor="w", padx=36, pady=(0, 16))

        # Botón analizar
        tk.Button(self.root, text="Analizar URL",
                  font=("Segoe UI", 12), bg="#1a1a1a", fg="white",
                  relief="flat", cursor="hand2", pady=10,
                  command=self.analizar).pack(padx=36, fill="x")

    def metrica(self, parent, label, valor, col):
        f = tk.Frame(parent, bg="white", padx=12, pady=8)
        f.grid(row=0, column=col, sticky="ew",
               padx=(0 if col == 0 else 6, 0))
        parent.columnconfigure(col, weight=1)
        tk.Label(f, text=label, font=("Segoe UI", 8),
                 bg="white", fg="#aaa").pack(anchor="w")
        lbl = tk.Label(f, text=valor,
                        font=("Segoe UI", 12, "bold"),
                        bg="white", fg="#1a1a1a")
        lbl.pack(anchor="w")
        return lbl

    def dibujar_barra(self, score):
        self.canvas_barra.update_idletasks()
        ancho = self.canvas_barra.winfo_width()
        self.canvas_barra.delete("all")
        self.canvas_barra.create_rectangle(
            0, 0, ancho, 10, fill="#e8e8e8", outline="")
        if score > 0:
            color = ("#27ae60" if score < 30 else
                     "#f39c12" if score < 60 else "#e74c3c")
            self.canvas_barra.create_rectangle(
                0, 0, int(ancho * score / 100), 10,
                fill=color, outline="")

    def analizar(self):
        url = self.entrada.get().strip()
        if not url:
            return

        self.lbl_nivel.config(text="Analizando...", fg="#aaa")
        self.lbl_señales.config(text="Consultando bases de datos...", fg="#aaa")
        self.lbl_vt.config(text="")

        threading.Thread(target=self.procesar, args=(url,), daemon=True).start()

    def procesar(self, url):
        r = analizar(url)
        apis = verificar_todas(url)

        colores = {
            "SEGURO":      "#27ae60",
            "BAJO RIESGO": "#27ae60",
            "SOSPECHOSO":  "#f39c12",
            "PELIGROSO":   "#e74c3c",
        }

        self.root.after(0, lambda: self.actualizar(r, apis, colores))

    def actualizar(self, r, apis, colores):
        self.dibujar_barra(r["score"])
        self.lbl_nivel.config(text=r["nivel"],
                               fg=colores[r["nivel"]])
        self.lbl_dominio.config(text=r["dominio"])
        self.lbl_https.config(text="Si" if r["usa_https"] else "No",
                               fg="#27ae60" if r["usa_https"] else "#e74c3c")
        self.lbl_score.config(text=f"{r['score']}/100")

        if r["señales"]:
            texto = "\n".join(f"!! {s}" for s in r["señales"])
            self.lbl_señales.config(text=texto, fg="#e74c3c")
        else:
            self.lbl_señales.config(
                text="No se detectaron señales sospechosas", fg="#27ae60")

        vt = apis["virustotal"]
        if not vt["disponible"]:
            self.lbl_vt.config(
                text=f"VirusTotal: No disponible ({vt['razon']})", fg="#aaa")
        elif vt["limpia"]:
            self.lbl_vt.config(
                text=f"VirusTotal: Limpia — 0/{vt['total']} motores",
                fg="#27ae60")
        else:
            self.lbl_vt.config(
                text=f"VirusTotal: DETECTADA — {vt['maliciosas']} maliciosa(s), {vt['sospechosas']} sospechosa(s)",
                fg="#e74c3c")

root = tk.Tk()
App(root)
root.mainloop()