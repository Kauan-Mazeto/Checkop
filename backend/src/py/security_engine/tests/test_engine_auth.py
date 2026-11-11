import os
import unittest

# precisa existir antes de importar o app: sem ENGINE_TOKEN o motor se recusa a subir
os.environ["ENGINE_TOKEN"] = "token-de-teste"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
PROTECTED_ROUTES = ["/scans/nuclei", "/scans/zap", "/scans/subdomains", "/scans/sast", "/templates/update"]


class EngineTokenTest(unittest.TestCase):
    # B4: só quem tem o token (a API Node) pode disparar varreduras.

    def test_health_continua_aberto(self):
        self.assertEqual(client.get("/health").status_code, 200)

    def test_rotas_sem_token_retornam_401(self):
        for route in PROTECTED_ROUTES:
            with self.subTest(route=route):
                self.assertEqual(client.post(route, json={}).status_code, 401)

    def test_token_errado_retorna_401(self):
        resp = client.post("/scans/sast", json={"files": {}}, headers={"X-Engine-Token": "errado"})
        self.assertEqual(resp.status_code, 401)

    def test_token_correto_passa_da_autenticacao(self):
        # corpo inválido de propósito: 422 prova que passou do token sem rodar ferramenta nenhuma
        resp = client.post("/scans/nuclei", json={}, headers={"X-Engine-Token": "token-de-teste"})
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
