import unittest

from app.cwe_catalog import cwe_numbers, describe
from app.sast_runner import _dedupe_results, _parse_result


def result(line, check_id, severity, cwe):
    return {
        "check_id": check_id,
        "path": "/tmp/x/App.java",
        "start": {"line": line},
        "end": {"line": line},
        "extra": {"severity": severity, "message": "msg", "lines": "codigo", "metadata": {"cwe": [cwe]}},
    }


class SastPresentationTest(unittest.TestCase):
    def test_mesma_falha_por_duas_regras_vira_um_achado_so(self):
        # caso real: p/default e p/security-audit acusam o mesmo SQL Injection na linha 21
        results = [
            result(21, "java.lang.security.audit.formatted-sql-string", "ERROR", "CWE-89: SQL Injection"),
            result(21, "java.lang.security.audit.sqli.jdbc-sqli", "WARNING", "CWE-89: SQL Injection"),
            result(27, "java.lang.security.audit.crypto.ecb-cipher", "WARNING", "CWE-327: Broken Crypto"),
            result(27, "java.lang.security.audit.crypto.use-of-aes-ecb", "WARNING", "CWE-327: Broken Crypto"),
        ]
        unique = _dedupe_results(results)
        self.assertEqual(len(unique), 2)
        sqli = next(r for r in unique if r["start"]["line"] == 21)
        self.assertEqual(sqli["extra"]["severity"], "ERROR")  # mantém a mais grave
        self.assertEqual(sqli["_rule_count"], 2)

    def test_falhas_diferentes_na_mesma_linha_continuam_separadas(self):
        results = [result(5, "a", "ERROR", "CWE-89"), result(5, "b", "WARNING", "CWE-798")]
        self.assertEqual(len(_dedupe_results(results)), 2)

    def test_titulo_e_correcao_vem_da_classe_da_falha(self):
        finding = _parse_result(
            {**result(21, "java.lang.security.audit.formatted-sql-string", "ERROR", "CWE-89: SQL Injection"), "_rule_count": 2},
            "/tmp/x", {}, {},
        )
        self.assertTrue(finding.title.startswith("SQL Injection"))
        self.assertIn("parametrizadas", finding.remediation)
        self.assertIn("Confirmado por 2 regras", finding.description)
        self.assertEqual(finding.severity, "HIGH")

    def test_cwe_desconhecida_usa_o_nome_da_regra(self):
        finding = _parse_result(result(3, "x.y.regra-nova", "INFO", "CWE-99999"), "/tmp/x", {}, {})
        self.assertTrue(finding.title.startswith("Regra nova"))

    def test_extrai_numeros_de_cwe(self):
        self.assertEqual(cwe_numbers(["CWE-89: SQL", "CWE-564"]), ["89", "564"])
        self.assertEqual(cwe_numbers("CWE-327"), ["327"])
        self.assertIsNone(describe(["99999"]))


if __name__ == "__main__":
    unittest.main()
