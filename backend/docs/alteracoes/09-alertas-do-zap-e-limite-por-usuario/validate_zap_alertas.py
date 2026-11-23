"""Validação real da alteração 09 (alertas antigos e varreduras em paralelo) com o ZAP do Docker (roda dentro do container do motor)."""
import asyncio, http.server, sys, threading, time
sys.path.insert(0, "/app")
from app.zap_runner import run_zap_scan

FIXED = {"on": False}


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if FIXED["on"]:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>teste</h1><a href='/a'>a</a></body></html>")

    def log_message(self, *a):
        pass


def show(label, result, t0):
    findings, duration, warnings = result
    print(f"{label}: {len(findings)} achado(s), {duration:.0f}s, terminou em t={time.monotonic() - t0:.0f}s")
    for name in sorted({f.title for f in findings}):
        print("   -", name)
    hosts = sorted({(f.affectedUrl or "").split("/")[2] for f in findings if f.affectedUrl})
    print("   hosts nos achados:", hosts)
    for w in warnings:
        print("   aviso:", w)


async def main():
    t0 = time.monotonic()
    show("A) site sem cabeçalhos", await run_zap_scan("http://localhost:3999", safe_mode=True, active_scan=False), t0)
    FIXED["on"] = True
    t0 = time.monotonic()
    site, lab = await asyncio.gather(
        run_zap_scan("http://localhost:3999", safe_mode=True, active_scan=False),
        run_zap_scan("http://localhost:3000", safe_mode=True, active_scan=False),
    )
    show("B) site corrigido (em paralelo com C)", site, t0)
    show("C) laboratório (em paralelo com B)", lab, t0)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 3999), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
asyncio.run(main())
srv.shutdown()
