"""Alertas antigos do ZAP não voltam numa varredura nova (alteração 09)."""

import asyncio
import unittest
from unittest import mock

from app import zap_runner
from app.zap_runner import ZapExecutionError
from tests.test_zap_objectives import FakeZap

TARGET = "http://localhost:3000"


def scan():
    return zap_runner.run_zap_scan(TARGET, safe_mode=False, active_scan=True, scanner_ids=["40018"])


def fake_with_old_alerts(old, per_round, fail=False):
    """ZAP falso com `old` alertas antigos no alvo; cada deleteAlerts apaga `per_round` (o 2.17 apaga em lotes)."""
    fake = FakeZap()
    original = fake.get
    state = {"left": old}

    async def get(client, path, params):
        if path == "/JSON/core/view/numberOfAlerts/":
            fake.calls.append((path, dict(params)))
            return {"numberOfAlerts": str(state["left"])}
        if path == "/JSON/alert/action/deleteAlerts/":
            fake.calls.append((path, dict(params)))
            if fail:
                raise ZapExecutionError("bad_action")
            state["left"] = max(0, state["left"] - per_round)
            return {"deleteAlerts": "ok"}
        return await original(client, path, params)

    fake.get = get
    return fake, state


class ClearTargetAlertsTest(unittest.TestCase):
    def setUp(self):
        zap_runner._beta_addons_ready = True

    def run_scan(self, fake):
        with mock.patch.object(zap_runner, "_get", fake.get):
            return asyncio.run(scan())

    def test_apaga_os_alertas_antigos_do_alvo_antes_de_acessar_o_site(self):
        # regressão: sem isso, falha já corrigida voltava como "persistente"
        fake, state = fake_with_old_alerts(old=78, per_round=46)
        _, _, warnings = self.run_scan(fake)
        paths = fake.paths()
        self.assertEqual(state["left"], 0)
        self.assertEqual(paths.count("/JSON/alert/action/deleteAlerts/"), 2)  # repete até zerar
        self.assertLess(paths.index("/JSON/alert/action/deleteAlerts/"), paths.index("/JSON/core/action/accessUrl/"))
        self.assertEqual(warnings, [])

    def test_so_apaga_o_alvo_desta_varredura_nunca_a_sessao_toda(self):
        # newSession apagaria a varredura em andamento de outro usuário
        fake, _ = fake_with_old_alerts(old=5, per_round=5)
        self.run_scan(fake)
        deletes = [p for path, p in fake.calls if path == "/JSON/alert/action/deleteAlerts/"]
        self.assertEqual(deletes, [{"baseurl": TARGET}])
        self.assertNotIn("/JSON/core/action/newSession/", fake.paths())
        self.assertNotIn("/JSON/core/action/deleteAllAlerts/", fake.paths())

    def test_sem_alertas_antigos_nao_apaga_nada(self):
        fake, _ = fake_with_old_alerts(old=0, per_round=1)
        self.run_scan(fake)
        self.assertNotIn("/JSON/alert/action/deleteAlerts/", fake.paths())

    def test_falha_na_limpeza_avisa_e_a_varredura_segue(self):
        fake, _ = fake_with_old_alerts(old=3, per_round=1, fail=True)
        findings, _, warnings = self.run_scan(fake)
        self.assertEqual(len(findings), 1)
        self.assertTrue(any("anteriores podem aparecer" in w for w in warnings))

    def test_limpeza_que_nunca_zera_desiste_com_aviso(self):
        fake, _ = fake_with_old_alerts(old=10, per_round=0)
        _, _, warnings = self.run_scan(fake)
        self.assertEqual(fake.paths().count("/JSON/alert/action/deleteAlerts/"), zap_runner.CLEAR_ALERTS_MAX_ROUNDS)
        self.assertTrue(any("anteriores podem aparecer" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
