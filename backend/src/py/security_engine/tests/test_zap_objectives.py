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
            # formato real da API 2.17: risco por extenso, sem "riskcode"
            return {"alerts": [{"pluginId": "40018", "name": "SQL Injection", "risk": "High", "confidence": "Low", "cweid": "89"}]}
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
        # SQLi (CWE-89): vetor AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8, crítico pela escala oficial
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].cvssScore, 9.8)
        self.assertEqual(findings[0].cvssSource, "CWE")
        self.assertEqual(findings[0].confidence, "LOW")
        self.assertTrue(any("90018" in w for w in warnings))


class AlertSeverityTest(unittest.TestCase):
    def test_risco_por_extenso_da_api(self):
        # regressão: a API não manda "riskcode"; todo achado do ZAP virava INFO
        for risk, expected in (("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW"), ("Informational", "INFO")):
            self.assertEqual(zap_runner._parse_alert({"pluginId": "1", "risk": risk}).severity, expected)

    def test_riskcode_dos_relatorios_continua_aceito(self):
        self.assertEqual(zap_runner._parse_alert({"pluginId": "1", "riskcode": "2"}).severity, "MEDIUM")


class SpaDetectionTest(unittest.TestCase):
    STATIC = "<html><body><h1>Loja</h1><nav><a href='/a'>A</a></nav><p>" + "Texto de verdade. " * 20 + "</p></body></html>"

    def test_site_comum_nao_aciona_o_ajax(self):
        self.assertIsNone(zap_runner.detect_spa(self.STATIC, pages_found=9))

    def test_raiz_de_framework(self):
        for html in ("<app-root></app-root>", '<div id="root"></div>', '<html ng-version="20.0.0">', "<div id='__next'></div>"):
            self.assertIsNotNone(zap_runner.detect_spa(html, pages_found=9), html)

    def test_pagina_montada_por_javascript(self):
        html = "<html><body><div id='main'></div><script src='/bundle.js'></script></body></html>"
        self.assertIn("JavaScript", zap_runner.detect_spa(html, pages_found=9))

    def test_poucos_links_com_javascript(self):
        html = self.STATIC.replace("</body>", "<script src='/app.js'></script></body>")
        self.assertIsNotNone(zap_runner.detect_spa(html, pages_found=1))
        self.assertIsNone(zap_runner.detect_spa(self.STATIC, pages_found=1))  # sem JS: é só um site pequeno


class AutoAjaxTest(unittest.TestCase):
    def setUp(self):
        zap_runner._beta_addons_ready = True
        patcher = mock.patch.object(zap_runner, "AJAX_SPIDER_START_POLL_SECONDS", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_espera_o_ajax_comecar_antes_de_considerar_terminado(self):
        # regressão: o 1º "stopped" (navegador ainda subindo) era lido como fim
        statuses = iter(["stopped", "stopped", "running", "running", "stopped"])
        fake = self._fake("<app-root></app-root>")
        inner = fake.get

        async def get(client, path, params):
            if path == "/JSON/ajaxSpider/view/status/":
                fake.calls.append((path, dict(params)))
                return {"status": next(statuses, "stopped")}
            return await inner(client, path, params)

        fake.get = get
        with mock.patch.object(zap_runner, "POLL_INTERVAL_SECONDS", 0):
            _, _, warnings = run(lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=["40018"]), fake)
        status_calls = [p for p in fake.paths() if p == "/JSON/ajaxSpider/view/status/"]
        self.assertGreaterEqual(len(status_calls), 5)
        self.assertFalse(any("não encontrou páginas" in w for w in warnings))

    def _fake(self, html):
        fake = FakeZap()
        original = fake.get

        async def get(client, path, params):
            if path == "/JSON/core/view/messages/":
                fake.calls.append((path, dict(params)))
                return {"messages": [{"responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html", "responseBody": html}]}
            if path == "/JSON/spider/view/results/":
                fake.calls.append((path, dict(params)))
                return {"results": ["http://localhost:3000/"]}
            if path == "/JSON/ajaxSpider/view/status/":
                fake.calls.append((path, dict(params)))
                return {"status": "stopped"}
            if path == "/JSON/ajaxSpider/view/numberOfResults/":
                return {"numberOfResults": "5"}
            return await original(client, path, params)

        fake.get = get
        return fake

    def test_spa_detectada_aciona_o_ajax_e_avisa(self):
        fake = self._fake("<app-root></app-root>")
        _, _, warnings = run(lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=["40018"]), fake)
        self.assertIn("/JSON/ajaxSpider/action/scan/", fake.paths())
        self.assertIn(("/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/", {"Integer": str(zap_runner.AJAX_SPIDER_BROWSERS)}), fake.calls)
        self.assertTrue(any("SPA" in w for w in warnings))

    def test_site_comum_nao_aciona_o_ajax(self):
        fake = self._fake(SpaDetectionTest.STATIC)
        run(lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=["40018"]), fake)
        self.assertNotIn("/JSON/ajaxSpider/action/scan/", fake.paths())


class NucleiReachabilityTest(unittest.TestCase):
    def test_usa_o_dns_do_sistema(self):
        # regressão: sem -sr o Nuclei não resolvia "localhost" e terminava calado
        with mock.patch.object(nuclei_runner, "NUCLEI_BINARY", "nuclei"):
            command = nuclei_runner._build_command("http://localhost:3000", False, 10)
        self.assertIn("-sr", command)
        self.assertNotIn("-silent", command)

    def test_alvo_descartado_vira_aviso(self):
        stderr = '[INF] Skipped localhost:3000 from target list as found unresponsive permanently: cause="no address found for host"'
        self.assertIsNotNone(nuclei_runner.unreachable_warning(stderr))
        self.assertIsNone(nuclei_runner.unreachable_warning("[INF] Scan completed in 2s. No results found."))


class NucleiRuleIdTest(unittest.TestCase):
    def test_template_id_vira_rule_id(self):
        line = json.dumps({"template-id": "generic-sqli", "info": {"name": "SQLi", "severity": "high", "tags": ["sqli"]}})
        self.assertEqual(nuclei_runner._parse_line(line).ruleId, "generic-sqli")


if __name__ == "__main__":
    unittest.main()
