import requests
import time
import json

url = "http://127.0.0.1:8000/api/events/process"
msg = json.dumps({
    "timestamp": "2026-09-14T01:24:00Z",
    "level": "INFO",
    "service": "user-auth",
    "message": "User login failed",
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "action": "LOGIN"
})
payload = {"raw_message": msg, "source": "auth_json"}

print("--- RUN 1 ---")
r1 = requests.post(url, json=payload)
print(r1.json().get("processing_mode"))

print("Waiting for 3s...")
time.sleep(3)

print("--- RUN 2 ---")
r2 = requests.post(url, json=payload)
print(r2.json().get("processing_mode"))
print("Parser ID:", r2.json().get("parser_id"))
