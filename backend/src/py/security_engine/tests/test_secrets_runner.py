import unittest

from app.schemas import Finding
from app.secrets_runner import dedupe_findings, parse_gitleaks_report


class GitleaksParseTest(unittest.TestCase):
    def test_relatorio_vira_achado_de_credencial_fixa(self):
        report = [{
            "File": "C:\\tmp\\abc\\src\\config.js",
            "StartLine": 2,
            "EndLine": 2,
            "RuleID": "github-pat",
            "Description": "GitHub Personal Access Token",
            "Match": "REDACTED",
        }]
        contents = {"src/config.js": "const a = 1;\nconst t = 'REDACTED';\n"}

        [finding] = parse_gitleaks_report(report, "C:\\tmp\\abc", contents)

        self.assertEqual(finding.title, "Credencial fixa no código (src/config.js:2)")
        self.assertEqual(finding.affectedUrl, "src/config.js:2")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("GitHub Personal Access Token", finding.description)
        self.assertEqual(finding.rawResponse, "const t = 'REDACTED';")
        self.assertTrue(finding.owaspUrl.startswith("A07"))

    def test_relatorio_vazio(self):
        self.assertEqual(parse_gitleaks_report([], "/tmp", {}), [])


class DedupeTest(unittest.TestCase):
    def test_mesmo_segredo_por_duas_ferramentas_vira_um(self):
        a = Finding(title="Credencial fixa no código (a.js:2)", severity="HIGH", tool="SAST", affectedUrl="a.js:2")
        b = Finding(title="Credencial fixa no código (a.js:2)", severity="HIGH", tool="SAST", affectedUrl="a.js:2-3")
        c = Finding(title="SQL Injection (a.js:2)", severity="HIGH", tool="SAST", affectedUrl="a.js:2")
        self.assertEqual(len(dedupe_findings([a, b, c])), 2)


if __name__ == "__main__":
    unittest.main()
