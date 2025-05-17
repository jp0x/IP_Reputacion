import os
import requests
from openai import OpenAI
from dotenv import load_dotenv

# Cargar claves API desde .env
load_dotenv()
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY")
)

# === FUNCIONES DE CONSULTA ===

def check_abuseipdb(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if r.status_code == 200:
            data = r.json()["data"]
            return ("AbuseIPDB", data.get("abuseConfidenceScore", 0))
    except:
        pass
    return ("AbuseIPDB", "Error")

def check_otx(ip):
    api_key = os.getenv("OTX_API_KEY")
    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", headers=headers)
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return ("AlienVault OTX", pulses)
    except:
        pass
    return ("AlienVault OTX", "Error")

def check_virustotal(ip):
    api_key = os.getenv("VT_API_KEY")
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return ("VirusTotal", score)
    except:
        pass
    return ("VirusTotal", "Error")

def check_greynoise(ip):
    api_key = os.getenv("GREYNOISE_API_KEY")
    headers = {"key": api_key}
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if r.status_code == 200:
            data = r.json()
            classification = data.get("classification", "unknown")
            score = {"benign": 0, "unknown": 1, "malicious": 3}.get(classification, 1)
            return ("GreyNoise", score)
    except:
        pass
    return ("GreyNoise", "Error")

# === GENERADOR DE ANALISIS CON LLaMA ===

def analizar_tabla(ip, tabla):
    prompt = f"""
Actúa como un analista de inteligencia de amenazas.

IP objetivo: {ip}

Tabla de reputación:
{tabla}

Primero, resume brevemente qué se encontró en línea para esta IP considerando los puntajes de las fuentes.

Luego, entrega una conclusión clara:
- ¿La IP se considera benigna, maliciosa o indeterminada?
- ¿Qué acción se recomienda al equipo MDR o SOC?

Usa un lenguaje formal, técnico y en español. No uses emojis.
    """.strip()

    completion = client.chat.completions.create(
        model="meta-llama/llama-3.3-8b-instruct:free",
        messages=[{"role": "user", "content": prompt}],
        extra_headers={
            "HTTP-Referer": "https://yourdomain.com",
            "X-Title": "IP_Reputation_Report"
        }
    )
    return completion.choices[0].message.content.strip()

def main():
    print("== Analyst_CortexXDR – Reputación de IP con conclusión final ==")
    ip = input("IP a analizar: ").strip()
    tabla_raw = []
    tabla_mostrar = []

    for check_func in [check_abuseipdb, check_otx, check_virustotal, check_greynoise]:
        fuente, reputacion = check_func(ip)
        tabla_raw.append(f"{fuente}	{ip}	{reputacion}")
        tabla_mostrar.append((fuente, reputacion))

    print(f"\nIP a analizar: {ip}")
    print("\n--- Tabla de reputación ---")
    print(f"{'Fuente':<20} | {'Puntaje'}")
    print("-" * 35)
    for fuente, rep in tabla_mostrar:
        print(f"{fuente:<20} | {rep}")

    tabla_texto = "\n".join(tabla_raw)
    resultado = analizar_tabla(ip, tabla_texto)

    print("\n--- Resumen y conclusión ---\n")
    print(resultado)

    with open("reputacion_ip_resultado.txt", "w", encoding="utf-8") as f:
        f.write(f"IP analizada: {ip}\n\nTabla de reputación:\n")
        for fuente, rep in tabla_mostrar:
            f.write(f"{fuente:<20} | {rep}\n")
        f.write("\nResumen y análisis:\n\n")
        f.write(resultado)

    print("\nResultado guardado en reputacion_ip_resultado.txt")

if __name__ == "__main__":
    main()