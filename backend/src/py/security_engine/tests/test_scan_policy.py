import asyncio
import unittest
from unittest import mock

from app import nuclei_runner, zap_runner
from app.zap_runner import should_run_active_scan


class ActiveScanPolicyTest(unittest.TestCase):
    def test_sem_instrucao_mantem_regra_antiga(self):
        self.assertFalse(should_run_active_scan(safe_mode=True, active_scan=None))
        self.assertTrue(should_run_active_scan(safe_mode=False, active_scan=None))

    def test_instrucao_explicita_do_node_prevalece(self):
        # produção verificada + opt-in
        self.assertTrue(should_run_active_scan(safe_mode=True, active_scan=True))
        # público sem opt-in
        self.assertFalse(should_run_active_scan(safe_mode=False, active_scan=False))


class ZapThrottlingTest(unittest.TestCase):
    # RF-51: em produção o ativo roda devagar para não derrubar o site

    def _run(self, safe_mode):
        calls = []

        async def fake_get(client, path, params):
            calls.append((path, params))
            return {}

        with mock.patch.object(zap_runner, "_get", fake_get):
            asyncio.run(zap_runner._set_active_scan_throttling(None, safe_mode))
        return dict(calls)

    def test_producao_usa_poucas_threads_e_delay(self):
        calls = self._run(safe_mode=True)
        self.assertEqual(calls["/JSON/ascan/action/setOptionThreadPerHost/"]["Integer"], "2")
        self.assertEqual(calls["/JSON/ascan/action/setOptionDelayInMs/"]["Integer"], "250")

    def test_local_zera_o_delay_herdado_da_varredura_anterior(self):
        calls = self._run(safe_mode=False)
        self.assertEqual(calls["/JSON/ascan/action/setOptionDelayInMs/"]["Integer"], "0")


class NucleiExcludedTagsTest(unittest.TestCase):
    def _etags(self, safe_mode):
        with mock.patch.object(nuclei_runner, "NUCLEI_BINARY", "nuclei"):
            command = nuclei_runner._build_command("https://exemplo.com", safe_mode, 10)
        return command[command.index("-etags") + 1].split(",")

    def test_modo_seguro_exclui_templates_intrusivos(self):
        self.assertEqual(set(self._etags(True)), {"dos", "fuzz", "intrusive"})

    def test_dos_fica_bloqueado_mesmo_com_ataque_liberado(self):
        self.assertEqual(self._etags(False), ["dos"])


if __name__ == "__main__":
    unittest.main()
