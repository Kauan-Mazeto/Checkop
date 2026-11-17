import asyncio
import unittest
from unittest import mock

from app import translator


class LanguageTest(unittest.TestCase):
    def test_normaliza_o_codigo(self):
        self.assertEqual(translator.normalize_language("pt-br"), "pt-BR")
        self.assertEqual(translator.normalize_language("ES"), "es")
        self.assertEqual(translator.normalize_language(None), "pt-BR")

    def test_recusa_codigo_invalido(self):
        for bad in ("", "português", "en|pt", "../x"):
            with self.assertRaises(translator.UnsupportedLanguageError):
                translator.normalize_language(bad or "!")

    def test_codigo_do_deepl(self):
        self.assertEqual(translator._deepl_target("pt-BR"), "PT-BR")
        self.assertEqual(translator._deepl_target("pt"), "PT-BR")
        self.assertEqual(translator._deepl_target("es"), "ES")
        self.assertEqual(translator._deepl_target("zh-CN"), "ZH-HANS")


class TranslateManyTest(unittest.TestCase):
    def setUp(self):
        translator._cache.clear()

    def test_ingles_volta_igual_sem_chamar_api(self):
        with mock.patch.object(translator, "_mymemory") as api:
            result = asyncio.run(translator.translate_many({"Fix it."}, "en"))
        self.assertEqual(result, {"Fix it.": "Fix it."})
        api.assert_not_called()

    def test_traduz_para_o_idioma_pedido_e_guarda_por_idioma(self):
        calls = []

        async def fake(client, text, target):
            calls.append(target)
            return f"[{target}] {text}"

        with mock.patch.object(translator, "DEEPL_API_KEY", ""), mock.patch.object(translator, "_mymemory", fake):
            es = asyncio.run(translator.translate_many({"Fix it."}, "es"))
            fr = asyncio.run(translator.translate_many({"Fix it."}, "fr"))
            asyncio.run(translator.translate_many({"Fix it."}, "es"))  # do cache

        self.assertEqual(es["Fix it."], "[es] Fix it.")
        self.assertEqual(fr["Fix it."], "[fr] Fix it.")
        self.assertEqual(calls, ["es", "fr"])

    def test_deepl_manda_todos_os_textos_numa_requisicao(self):
        batches = []

        async def fake_batch(client, texts, target):
            batches.append(list(texts))
            for t in texts:
                translator._cache[(target, t)] = f"pt:{t}"

        texts = {f"Rule {i}." for i in range(60)}
        with mock.patch.object(translator, "DEEPL_API_KEY", "x:fx"), mock.patch.object(translator, "_deepl_batch", fake_batch):
            result = asyncio.run(translator.translate_many(texts, "pt-BR"))
        self.assertEqual(sorted(len(b) for b in batches), [10, 50])
        self.assertEqual(result["Rule 1."], "pt:Rule 1.")

    def test_falha_devolve_o_original_e_nao_entra_no_cache(self):
        async def broken(client, text, target):
            raise ValueError("cota")

        with mock.patch.object(translator, "DEEPL_API_KEY", ""), mock.patch.object(translator, "_mymemory", broken):
            result = asyncio.run(translator.translate_many({"Fix it."}, "es"))
        self.assertEqual(result, {"Fix it.": "Fix it."})
        self.assertNotIn(("es", "Fix it."), translator._cache)


if __name__ == "__main__":
    unittest.main()
