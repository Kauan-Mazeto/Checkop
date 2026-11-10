import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import local_env


class LocalEnvTest(unittest.TestCase):
    def test_le_o_env_sem_sobrescrever_o_ambiente(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text('# comentario\nCHECKOP_TESTE_A="valor a"\nCHECKOP_TESTE_B=do-arquivo\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"CHECKOP_TESTE_B": "do-ambiente"}):
                local_env.load_env_file(env_file)
                self.assertEqual(os.environ["CHECKOP_TESTE_A"], "valor a")
                self.assertEqual(os.environ["CHECKOP_TESTE_B"], "do-ambiente")
            os.environ.pop("CHECKOP_TESTE_A", None)

    def test_acha_os_binarios_da_pasta_tools(self):
        with mock.patch.object(local_env.shutil, "which", return_value=None):
            self.assertTrue(local_env.find_tool("nuclei").endswith(("nuclei.exe", "nuclei")))
            self.assertIsNone(local_env.find_tool("ferramenta-que-nao-existe"))


if __name__ == "__main__":
    unittest.main()
