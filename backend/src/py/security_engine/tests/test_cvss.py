import unittest

from app import cvss, zap_runner


class BaseScoreTest(unittest.TestCase):
    # notas conferidas na calculadora oficial do FIRST (cvss v3.1)
    KNOWN = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N": 4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N": 6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N": 7.2,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }

    def test_formula_oficial(self):
        for vector, expected in self.KNOWN.items():
            self.assertEqual(cvss.base_score(vector), expected, vector)

    def test_todos_os_vetores_por_cwe_sao_validos(self):
        for cwe, vector in cvss.CWE_VECTORS.items():
            self.assertGreater(cvss.base_score(vector), 0, cwe)

    def test_vetor_invalido(self):
        with self.assertRaises(cvss.InvalidVectorError):
            cvss.base_score("CVSS:3.1/AV:N/AC:L")
        with self.assertRaises(cvss.InvalidVectorError):
            cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class ScoreFindingTest(unittest.TestCase):
    def test_vetor_do_template_tem_prioridade(self):
        r = cvss.score_finding("HIGH", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", ["89"])
        self.assertEqual((r["cvssScore"], r["cvssSource"], r["severity"]), (10.0, "TEMPLATE", "CRITICAL"))

    def test_sem_vetor_usa_a_classe_pelo_cwe(self):
        r = cvss.score_finding("HIGH", None, ["CWE-79"])
        self.assertEqual((r["cvssScore"], r["cvssSource"], r["severity"]), (6.1, "CWE", "MEDIUM"))

    def test_sem_vetor_nem_cwe_conhecido_e_estimativa(self):
        r = cvss.score_finding("MEDIUM", None, ["99999"])
        self.assertEqual((r["cvssScore"], r["cvssSource"], r["severity"]), (5.5, "SEVERITY", "MEDIUM"))

    def test_informativo_continua_zero(self):
        r = cvss.score_finding("INFO", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ["89"])
        self.assertEqual((r["cvssScore"], r["severity"]), (0.0, "INFO"))


class ZapAlertTest(unittest.TestCase):
    def test_falso_positivo_do_zap_e_descartado(self):
        self.assertTrue(zap_runner.is_false_positive({"confidence": "False Positive"}))
        self.assertFalse(zap_runner.is_false_positive({"confidence": "Medium"}))

    def test_alerta_traz_vetor_e_confianca(self):
        f = zap_runner._parse_alert({"pluginId": "40012", "name": "XSS", "risk": "High", "confidence": "Medium", "cweid": "79"})
        self.assertEqual(f.cvssVector, cvss.CWE_VECTORS["79"])
        self.assertEqual(f.confidence, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
