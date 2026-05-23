from flask import Flask, request, jsonify, render_template
from analyzer import analizar
from apis import verificar_todas
import os

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analizar", methods=["POST"])
def api_analizar():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Sin URL"}), 400
    resultado = analizar(url)
    apis = verificar_todas(url)
    return jsonify({
        "resultado": resultado,
        "apis": apis
    })

if __name__ == "__main__":
    app.run(debug=True)