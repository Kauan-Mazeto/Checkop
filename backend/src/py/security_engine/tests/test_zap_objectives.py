import asyncio
import json
import unittest
from unittest import mock

from app import nuclei_runner, zap_runner
from app.zap_runner import ZapExecutionError


class FakeZap:
    """Simula a API do ZAP: registra as chamadas e responde por caminho."""

    def __init__(self, unknown_scanner_ids=(), installed_addons=("ascanrulesBeta", "pscanrulesBeta"), install_fails=False):
        self.calls = []
        self.unknown = set(unknown_scanner_ids)
        self.installed = list(installed_addons)
        self.install_fails = install_fails

    async def get(self, client, path, params):
        self.calls.append((path, dict(params)))
        if path == "/JSON/ascan/action/enableScanners/":
            if set(params["ids"].split(",")) & self.unknown:
                raise ZapExecutionError("does_not_exist")
        if path == "/JSON/autoupdate/view/installedAddons/":
            return {"installedAddons": [{"id": a} for a in self.installed]}
        if path == "/JSON/autoupdate/action/installAddon/" and self.install_fails:
            raise ZapExecutionError("sem internet")
        if path in ("/JSON/spider/action/scan/", "/JSON/ascan/action/scan/"):
            return {"scan": "1"}
        if path.endswith("/status/"):
            return {"status": "100"}
        if path == "/JSON/core/view/alerts/":
            return {"alerts": [{"pluginId": "40018", "name": "SQL Injection", "riskcode": "3", "cweid": "89"}]}
        return {}

    def paths(self):
        return [p for p, _ in self.calls]


def run(coro_fn, fake):
    with mock.patch.object(zap_runner, "_get", fake.get):
        return asyncio.run(coro_fn())


class ScannerSelectionTest(unittest.TestCase):
    def test_varredura_completa_reativa_todos_os_scanners(self):
        # regressão: antes, None não fazia nada e herdava a seleção da varredura anterior
        fake = FakeZap()
        run(lambda: zap_runner._set_active_scanners(None, None), fake)
        self.assertEqual(fake.paths(), ["/JSON/ascan/action/enableAllScanners/"])

    def test_usa_a_acao_enableScanners_que_existe_no_zap(self):
        # regressão: "setEnabledScanners" não existe na API do ZAP 2.17
        fake = FakeZap()
        missing = run(lambda: zap_runner._set_active_scanners(None, ["40018", "40019"]), fake)
        self.assertEqual(missing, [])
        self.assertIn(("/JSON/ascan/action/enableScanners/", {"ids": "40018,40019"}), fake.calls)
        self.assertNotIn("/JSON/ascan/action/setEnabledScanners/", fake.paths())

    def test_id_indisponivel_nao_derruba_e_e_informado(self):
        fake = FakeZap(unknown_scanner_ids={"90018"})
        missing = run(lambda: zap_runner._set_active_scanners(None, ["40018", "90018"]), fake)
        self.assertEqual(missing, ["90018"])
        self.assertIn(("/JSON/ascan/action/enableScanners/", {"ids": "40018"}), fake.calls)


class BetaAddonsTest(unittest.TestCase):
    def setUp(self):
        zap_runner._beta_addons_ready = False

    def test_instala_os_que_faltam_uma_unica_vez(self):
        fake = FakeZap(installed_addons=["pscanrulesBeta"])
        run(lambda: zap_runner.ensure_beta_addons(None), fake)
        run(lambda: zap_runner.ensure_beta_addons(None), fake)
        installs = [p for p, params in fake.calls if p.endswith("installAddon/")]
        self.assertEqual(installs, ["/JSON/autoupdate/action/installAddon/"])
        self.assertIn(("/JSON/autoupdate/action/installAddon/", {"id": "ascanrulesBeta"}), fake.calls)

    def test_falha_na_instalacao_vira_aviso(self):
        fake = FakeZap(installed_addons=[], install_fails=True)
        warnings = run(lambda: zap_runner.ensure_beta_addons(None), fake)
        self.assertEqual(len(warnings), 1)


class RunZapScanTest(unittest.TestCase):
    def setUp(self):
        zap_runner._beta_addons_ready = True

    def test_objetivo_passivo_nao_inicia_varredura_ativa(self):
        fake = FakeZap()
        run(lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=[]), fake)
        self.assertNotIn("/JSON/ascan/action/scan/", fake.paths())

    def test_achado_traz_o_id_da_regra_e_os_avisos(self):
        fake = FakeZap(unknown_scanner_ids={"90018"})
        findings, _, warnings = run(
            lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=["40018", "90018"]),
            fake,
        )
        self.assertEqual(findings[0].ruleId, "40018")
        self.assertTrue(any("90018" in w for w in warnings))


class NucleiRuleIdTest(unittest.TestCase):
    def test_template_id_vira_rule_id(self):
        line = json.dumps({"template-id": "generic-sqli", "info": {"name": "SQLi", "severity": "high", "tags": ["sqli"]}})
        self.assertEqual(nuclei_runner._parse_line(line).ruleId, "generic-sqli")


if __name__ == "__main__":
    unittest.main()
