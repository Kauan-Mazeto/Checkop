"""Reproduz o item 1.1: alertas antigos do ZAP voltando numa varredura nova.

Sobe um site descartável na porta 3999 (dentro do container do motor, que o ZAP
enxerga como localhost), varre, "corrige" o site e varre de novo.
Uso: python repro.py [--new-session]
"""
import http.server, os, sys, threading, time
import httpx

ZAP = "http://localhost:8091"
KEY = os.environ.get("ZAP_API_KEY", "")
TARGET = "http://localhost:3999"
FIXED = {"on": False}
NEW_SESSION = "--new-session" in sys.argv


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><body><h1>teste</h1><a href='/a'>a</a></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if FIXED["on"]:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def g(path, **q):
    return httpx.get(ZAP + path, params={"apikey": KEY, **q}, timeout=60).json()


def scan(label):
    if NEW_SESSION:
        g("/JSON/core/action/newSession/", name="", overwrite="true")
    g("/JSON/core/action/accessUrl/", url=TARGET)
    sid = g("/JSON/spider/action/scan/", url=TARGET, recurse="true")["scan"]
    while int(g("/JSON/spider/view/status/", scanId=sid)["status"]) < 100:
        time.sleep(1)
    while int(g("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) > 0:
        time.sleep(1)
    names = sorted({a["name"] for a in g("/JSON/core/view/alerts/", baseurl=TARGET)["alerts"]})
    print(f"{label}: {len(names)} tipo(s) de alerta")
    for n in names:
        print("   -", n)
    return set(names)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 3999), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
print("modo:", "newSession antes de cada varredura" if NEW_SESSION else "sessão compartilhada (código atual)")
before = scan("1ª varredura (site sem cabeçalhos)")
FIXED["on"] = True
after = scan("2ª varredura (site corrigido)")
print("alertas que já deveriam ter sumido:", sorted(before & after - {"Modern Web Application"}) or "nenhum")
srv.shutdown()
