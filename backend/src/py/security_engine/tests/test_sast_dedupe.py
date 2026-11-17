import unittest

from app.sast_runner import _dedupe_results, _parse_result, vulnerability_class


def r(rule, start, end=None, cwe=None, severity="WARNING", path="/tmp/x/app.py"):
    return {
        "check_id": f"pkg.{rule}", "path": path,
        "start": {"line": start}, "end": {"line": end or start},
        "extra": {"severity": severity, "message": "m", "metadata": {"cwe": [cwe] if cwe else []}},
    }


class DedupeTest(unittest.TestCase):
    def test_mesma_falha_em_linhas_sobrepostas_vira_um_achado(self):
        # regressão: 5 regras no mesmo SQLi (uma com CWE errado) viravam 4 achados
        results = [
            r("sql-injection-db-cursor-execute", 8, 11, "CWE-89: SQL Injection", "ERROR"),
            r("formatted-sql-query", 11, cwe="CWE-89: SQL Injection"),
            r("tainted-sql-string", 11, cwe="CWE-915: Mass assignment", severity="ERROR"),
            r("tainted-sql-string", 11, cwe="CWE-704: Incorrect cast", severity="ERROR"),
        ]
        unique = _dedupe_results(results)
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0]["_rule_count"], 3)
        self.assertEqual(unique[0]["start"]["line"], 11)  # o trecho mais preciso, empatando a gravidade

    def test_falhas_diferentes_na_mesma_linha_continuam_separadas(self):
        results = [
            r("checkop-tls-verification-disabled-cli", 3, cwe="CWE-295: cert"),
            r("checkop-pipe-download-to-shell", 3, cwe="CWE-494: integrity"),
            r("curl-pipe-bash", 3, cwe="CWE-95: eval"),
        ]
        classes = sorted(u["_class"] for u in _dedupe_results(results))
        self.assertEqual(classes, ["integrity", "tls"])

    def test_mesma_classe_em_linhas_distantes_sao_dois_achados(self):
        results = [r("formatted-sql-query", 5, cwe="CWE-89"), r("formatted-sql-query", 40, cwe="CWE-89")]
        self.assertEqual(len(_dedupe_results(results)), 2)

    def test_classe_pelo_nome_da_regra_vence_cwe_errado(self):
        self.assertEqual(vulnerability_class(r("tainted-sql-string", 1, cwe="CWE-915")), "sqli")
        self.assertEqual(vulnerability_class(r("checkop-php-weak-password-hash", 1, cwe="CWE-916")), "crypto")

    def test_titulo_usa_o_cwe_da_regra_quando_e_da_mesma_classe(self):
        include = {**r("checkop-php-dynamic-include", 5, cwe="CWE-98: include", path="/tmp/x/a.php"), "_class": "path"}
        finding = _parse_result(include, "/tmp/x", {"a.php": "<?php\n"}, {})
        self.assertTrue(finding.title.startswith("Inclusão de arquivo"))
        wrong_cwe = {**r("tainted-sql-string", 1, cwe="CWE-915"), "_class": "sqli"}
        self.assertTrue(_parse_result(wrong_cwe, "/tmp/x", {"app.py": "x\n"}, {}).title.startswith("SQL Injection"))


if __name__ == "__main__":
    unittest.main()
