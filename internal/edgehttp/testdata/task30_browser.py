#!/usr/bin/env python3
import base64
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request

import websocket

deadline = time.monotonic() + 20
url, request_id = sys.argv[1], sys.argv[2]

def http_json(path, method="GET"):
    request = urllib.request.Request("http://127.0.0.1:29222" + path, method=method)
    with urllib.request.urlopen(request, timeout=max(.1, deadline-time.monotonic())) as response:
        return json.load(response)

targets = http_json("/json/list")
target = next((item for item in targets if item.get("type") == "page"), None)
if target is None:
    target = http_json("/json/new?" + urllib.parse.quote("about:blank", safe=""), "PUT")
ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=20, http_proxy_host=None, suppress_origin=True)
sequence = 0
events = []

def receive():
    ws.settimeout(max(.1, deadline-time.monotonic()))
    return json.loads(ws.recv())

def call(method, params=None):
    global sequence
    sequence += 1
    current = sequence
    ws.send(json.dumps({"id": current, "method": method, "params": params or {}}))
    while time.monotonic() < deadline:
        message = receive()
        if message.get("id") == current:
            if "error" in message:
                raise RuntimeError("CDP method failed")
            return message.get("result", {})
        events.append(message)
    raise TimeoutError("CDP method deadline")

call("Network.enable")
call("Network.setCacheDisabled", {"cacheDisabled": True})
call("Network.setBlockedURLs", {"urls": ["*/favicon.ico"]})
call("Network.setExtraHTTPHeaders", {"headers": {"X-Task30-ID": request_id}})
call("Page.enable")
events.clear()
navigate = call("Page.navigate", {"url": url})
if navigate.get("errorText"):
    print(json.dumps({"ok": False, "error_kind": "navigation", "error": navigate["errorText"]}))
    sys.exit(0)

edge, remote_address, loaded = "", "", False
while time.monotonic() < deadline and not loaded:
    message = events.pop(0) if events else receive()
    if message.get("method") == "Network.responseReceived" and message.get("params", {}).get("response", {}).get("url") == url:
        response = message["params"]["response"]
        edge = next((value for key, value in response.get("headers", {}).items() if key.lower() == "x-task30-edge"), "")
        remote_address = response.get("remoteIPAddress", "")
    if message.get("method") == "Page.loadEventFired":
        loaded = True
if not loaded:
    print(json.dumps({"ok": False, "error_kind": "deadline"}))
    sys.exit(0)
body = call("Runtime.evaluate", {"expression": "document.body.innerText", "returnByValue": True}).get("result", {}).get("value", "")
origin = urllib.parse.urlsplit(url)
certificate = call("Network.getCertificate", {"origin": f"{origin.scheme}://{origin.netloc}"}).get("tableNames", [])
fingerprint = hashlib.sha256(base64.b64decode(certificate[0])).hexdigest() if certificate else ""
ok = body.strip() == "paperboat-task30-browser-ready" and bool(edge) and bool(remote_address) and bool(fingerprint)
print(json.dumps({"ok": ok, "edge": edge, "remote_address": remote_address, "certificate": fingerprint, "body": body.strip()}))
