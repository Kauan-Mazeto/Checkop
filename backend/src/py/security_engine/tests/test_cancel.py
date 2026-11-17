import asyncio
import sys
import unittest
from unittest import mock

from app import jobs, nuclei_runner, zap_runner
from tests.test_zap_objectives import FakeZap, run


class JobsTest(unittest.TestCase):
    def test_nuclei_e_zap_da_mesma_varredura_compartilham_o_cancelamento(self):
        a = jobs.acquire("s1")
        b = jobs.acquire("s1")
        self.assertIs(a, b)
        self.assertTrue(jobs.cancel("s1"))
        self.assertTrue(a.is_set())
        jobs.release("s1")
        jobs.release("s1")
        self.assertFalse(jobs.cancel("s1"))  # nada mais rodando


class ZapCancelTest(unittest.TestCase):
    def setUp(self):
        zap_runner._beta_addons_ready = True

    def test_cancelado_para_o_spider_pula_o_ataque_e_devolve_o_que_achou(self):
        fake = FakeZap()
        original = fake.get

        async def get(client, path, params):
            if path == "/JSON/spider/view/status/":
                fake.calls.append((path, dict(params)))
                return {"status": "10"}  # nunca termina sozinho
            return await original(client, path, params)

        fake.get = get
        cancel = asyncio.Event()
        cancel.set()
        findings, _, warnings = run(
            lambda: zap_runner.run_zap_scan("http://localhost:3000", safe_mode=False, active_scan=True, scanner_ids=["40018"], cancel=cancel),
            fake,
        )
        self.assertIn("/JSON/spider/action/stop/", fake.paths())
        self.assertNotIn("/JSON/ascan/action/scan/", fake.paths())
        self.assertEqual(len(findings), 1)  # alertas que já existiam
        self.assertTrue(any("cancelada" in w for w in warnings))


class NucleiCancelTest(unittest.TestCase):
    def test_mata_o_processo_e_devolve_os_achados_ja_lidos(self):
        # processo falso: imprime um achado e fica "rodando" para sempre
        script = (
            "import json,sys,time;"
            "print(json.dumps({'template-id':'git-config','info':{'name':'Git','severity':'medium'},'matched-at':'http://x/.git/config'}));"
            "sys.stdout.flush();time.sleep(60)"
        )

        async def go():
            cancel = asyncio.Event()
            asyncio.get_running_loop().call_later(1.0, cancel.set)
            with mock.patch.object(nuclei_runner, "_build_command", lambda *a, **k: [sys.executable, "-c", script]):
                return await nuclei_runner.run_nuclei_scan("http://x", False, 10, None, cancel=cancel)

        findings, duration, warnings = asyncio.run(go())
        self.assertEqual([f.ruleId for f in findings], ["git-config"])
        self.assertLess(duration, 10)
        self.assertTrue(any("cancelada" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
