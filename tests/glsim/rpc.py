"""Tiny JSON-RPC helper for a local glsim server (no third-party client needed)."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


class RpcError(Exception):
    pass


class Sim:
    def __init__(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "run_glsim.py"), "--no-browser", "--port", str(self.port),
             "--seed", "7"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
        self.url = "http://127.0.0.1:%d/api" % self.port
        self._id = 0
        for _ in range(100):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/health" % self.port, timeout=1).read()
                return
            except Exception:
                time.sleep(0.2)
        self.close()
        raise RuntimeError("glsim did not start")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

    def rpc(self, _m, **params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": _m, "params": params}).encode()
        request = urllib.request.Request(self.url, data=body, headers={"content-type": "application/json"})
        try:
            reply = json.load(urllib.request.urlopen(request, timeout=180))
        except urllib.error.HTTPError as err:
            raise RpcError(err.read().decode()[:400])
        if "error" in reply:
            raise RpcError(reply["error"].get("message", str(reply["error"])))
        return reply["result"]

    def deploy(self, path, args, sender):
        return self.rpc("sim_deploy", code_path=os.path.join(ROOT, path), args=args, sender=sender)["contract_address"]

    def call(self, to, method, args=None, sender=None):
        return self.rpc("sim_call", to=to, method=method, args=args or [], sender=sender)["result"]

    def read(self, to, method, args=None):
        return self.rpc("sim_read", to=to, method=method, args=args or [])["result"]

    def read_json(self, to, method, args=None):
        value = self.read(to, method, args)
        return json.loads(value) if isinstance(value, str) and value[:1] in "{[" else value

    def set_time(self, iso):
        self.rpc("sim_setTime", datetime=iso)

    def mocks(self, web):
        self.rpc("sim_installMocks", web_mocks=web, llm_mocks={})
