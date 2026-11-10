import unittest

from app.mapping import A01, A03, A05, A06, A10, DEFAULT_OWASP_CATEGORY, map_to_owasp_category


class MapToOwaspCategoryTest(unittest.TestCase):
    # B1: antes da correção, toda tag caía no padrão A06.

    def test_cwe_tag_do_zap(self):
        self.assertEqual(map_to_owasp_category(["cwe-79"]), A03)

    def test_tag_do_nuclei(self):
        self.assertEqual(map_to_owasp_category(["sqli"]), A03)
        self.assertEqual(map_to_owasp_category(["ssrf"]), A10)
        self.assertEqual(map_to_owasp_category(["misconfig"]), A05)

    def test_codigo_owasp_explicito(self):
        self.assertEqual(map_to_owasp_category(["A01:2021"]), A01)

    def test_primeira_tag_reconhecida_vence(self):
        self.assertEqual(map_to_owasp_category(["tech", "wordpress", "lfi", "sqli"]), A01)

    def test_cwe_id_explicito_tem_prioridade_sobre_tags(self):
        self.assertEqual(map_to_owasp_category(["xss"], ["CWE-918"]), A10)

    def test_sem_sinal_reconhecido_usa_padrao(self):
        self.assertEqual(map_to_owasp_category(["tech", "panel-x"]), DEFAULT_OWASP_CATEGORY)
        self.assertEqual(map_to_owasp_category([]), DEFAULT_OWASP_CATEGORY)
        self.assertEqual(map_to_owasp_category(None), A06)


if __name__ == "__main__":
    unittest.main()
