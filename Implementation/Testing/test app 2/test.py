import requests

# Load XSS payloads from the uploaded cheatsheet file
with open("portswigger_cheatsheet.txt", "r", encoding="utf-8") as f:
    payloads = [line.strip() for line in f.readlines() if line.strip()]

URL = "http://127.0.0.1:5000/"  # Adjust if running on a different port

for i, payload in enumerate(payloads):
    response = requests.post(URL, data={"payload": payload})
    if payload in response.text:
        print(f"[Vulnerable] Payload {i+1}: {payload}")
    else:
        print(f"[Not Reflected] Payload {i+1}: {payload}")
