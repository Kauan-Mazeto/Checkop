import unittest

from app import zap_runner


def alert(**over):
    base = {
        "pluginId": "40018", "name": "SQL Injection", "risk": "High", "confidence": "Medium", "cweid": "89",
        "param": "id", "attack": "'", "evidence": "You have an error in your SQL syntax",
        "url": "http://localhost:3000/item?id=%27",
        "_message": {
            "requestHeader": "POST http://localhost:3000/login HTTP/1.1\r\nHost: localhost:3000\r\n"
                             "Content-Type: application/x-www-form-urlencoded\r\nCookie: sessionid=segredo\r\n"
                             "Authorization: Bearer token-real\r\n\r\n",
            "requestBody": "user=admin'&pass=x",
            "responseHeader": "HTTP/1.1 500 Internal Server Error\r\n\r\n",
            "responseBody": "x" * 2000 + "You have an error in your SQL syntax near ''' at line 1" + "y" * 2000,
        },
    }
    base.update(over)
    return base


class PocTest(unittest.TestCase):
    def test_traz_parametro_payload_requisicao_e_resposta(self):
        f = zap_runner._parse_alert(alert())
        self.assertEqual((f.parameter, f.attack), ("id", "'"))
        self.assertIn("POST http://localhost:3000/login", f.rawRequest)
        self.assertIn("user=admin'&pass=x", f.rawRequest)
        self.assertIn("HTTP/1.1 500 Internal Server Error", f.rawResponse)
        # trecho em volta da evidência, marcada; o resto do corpo é cortado
        self.assertIn(">>> You have an error in your SQL syntax <<<", f.rawResponse)
        self.assertLess(len(f.rawResponse), 2500)

    def test_sessao_nao_vai_para_o_relatorio(self):
        f = zap_runner._parse_alert(alert())
        self.assertNotIn("segredo", f.rawRequest)
        self.assertNotIn("token-real", f.rawRequest)
        self.assertIn("Cookie: [omitido no relatório]", f.rawRequest)
        self.assertNotIn("segredo", f.reproduction)

    def test_comando_curl_para_reproduzir(self):
        f = zap_runner._parse_alert(alert())
        self.assertTrue(f.reproduction.startswith('curl -i -X POST "http://localhost:3000/login"'))
        self.assertIn('-H "Content-Type: application/x-www-form-urlencoded"', f.reproduction)
        self.assertIn("--data-raw \"user=admin'&pass=x\"", f.reproduction)

    def test_sem_mensagem_fica_so_a_evidencia(self):
        f = zap_runner._parse_alert(alert(_message={}))
        self.assertEqual(f.rawResponse, "You have an error in your SQL syntax")
        self.assertIsNone(f.reproduction)


if __name__ == "__main__":
    unittest.main()
