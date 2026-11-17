"""Regras próprias do Checkop (app/rules/checkop): cada uma pega a falha e não
acusa a versão segura do mesmo código. Roda o Semgrep de verdade, só com as
regras locais (sem internet); pulado se o Semgrep não estiver instalado."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from app.sast_runner import CHECKOP_RULES_DIR, SAST_RULESETS

SEMGREP = shutil.which("semgrep")

# arquivo -> (código vulnerável, regras que devem disparar)
VULNERABLE = {
    "main.rs": ('use std::process::Command;\nfn f(h: &str){ Command::new("sh").arg("-c").arg(format!("ping {}", h)).output().unwrap(); }\n',
                {"checkop-rust-command-injection"}),
    "Main.kt": ('fun f(req: javax.servlet.http.HttpServletRequest, conn: java.sql.Connection) {\n'
                '  conn.createStatement().executeQuery("SELECT * FROM u WHERE n = \'" + req.getParameter("n") + "\'")\n'
                '  Runtime.getRuntime().exec("ping " + req.getParameter("h"))\n}\n',
                {"checkop-kotlin-sql-concat", "checkop-kotlin-command-injection"}),
    "Program.cs": ('using System.Diagnostics; using System.Security.Cryptography;\n'
                   'class A { void F(string n) {\n'
                   '  var c = "Server=.;Database=x;User Id=sa;Password=senha123;";\n'
                   '  Process.Start("cmd.exe", "/c ping " + n);\n  var m = MD5.Create();\n} }\n',
                   {"checkop-csharp-connection-string-password", "checkop-csharp-command-injection", "checkop-csharp-weak-crypto"}),
    "a.php": ("<?php\ninclude($_GET['page']);\n$h = md5($_POST['senha']);\nextract($_GET);\n",
              {"checkop-php-dynamic-include", "checkop-php-weak-password-hash", "checkop-php-extract-request"}),
    "deploy.sh": ('#!/bin/bash\ncurl -k https://x.com/i.sh | bash\neval "$1"\nchmod 777 /srv\n',
                  {"checkop-pipe-download-to-shell", "checkop-tls-verification-disabled-cli", "checkop-shell-eval-variable",
                   "checkop-world-writable-permissions"}),
    "Dockerfile": ("FROM node:latest\nADD https://x.com/a.tgz /a\nENV API_KEY=abc123\nRUN wget -qO- http://x.com/s | sh\n",
                   {"checkop-dockerfile-unpinned-image", "checkop-dockerfile-add-remote-url", "checkop-dockerfile-secret-in-env",
                    "checkop-pipe-download-to-shell"}),
    "main.tf": ('resource "aws_security_group" "w" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n', {"checkop-terraform-open-ingress"}),
    "i.html": ('<a href="https://x.com" target="_blank">x</a>\n<script>el.innerHTML = location.hash;</script>\n',
               {"checkop-html-target-blank-noopener", "checkop-html-dom-xss"}),
    "a.swift": ('import Foundation\nUserDefaults.standard.set(t, forKey: "authToken")\nlet p = Process(); p.arguments = ["-c", "ls " + dir]\n',
                {"checkop-swift-sensitive-userdefaults", "checkop-swift-shell-command"}),
    "a.js": ("const h = require('crypto').createHash('md5').update(x).digest('hex');\n", {"checkop-js-weak-hash"}),
    "S.scala": ('import scala.sys.process._\nobject S { def f(n: String) = s"ping $n".! }\n', {"checkop-scala-command-injection"}),
}

# mesma intenção, escrita do jeito seguro: nenhuma regra do Checkop pode disparar
SAFE = {
    "safe.rs": 'use std::process::Command;\nfn f(){ Command::new("sh").arg("-c").arg("echo ok").output().unwrap(); }\n',
    "Safe.kt": 'fun f(c: java.sql.Connection, n: String){ val s = c.prepareStatement("SELECT * FROM u WHERE n = ?"); s.setString(1, n) }\n',
    "Safe.cs": 'using System.Diagnostics;\nclass A { void F(){ Process.Start("notepad.exe"); var c = "Server=.;Integrated Security=true;"; } }\n',
    "safe.php": "<?php\ninclude 'header.php';\n$h = password_hash($_POST['senha'], PASSWORD_DEFAULT);\n",
    "safe.sh": '#!/bin/bash\ncurl -fsSL https://x.com/a.tgz -o a.tgz\nchmod 755 /usr/local/bin/app\n',
    "Dockerfile": "FROM node:20.11-alpine AS build\nUSER node\nENV NODE_ENV=production\nFROM scratch\n",
    "safe.tf": 'resource "aws_security_group" "w" {\n  ingress {\n    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n'
               '    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n',
    "safe.html": '<a href="https://x.com" target="_blank" rel="noopener noreferrer">x</a>\n<script>el.textContent = location.hash;</script>\n',
    "safe.swift": 'import Foundation\nUserDefaults.standard.set(true, forKey: "darkMode")\n',
    "safe.js": "const h = require('crypto').createHash('sha256').update(x).digest('hex');\n",
    "Safe.scala": 'import scala.sys.process._\nobject S { def f() = Seq("ls", "-la").! }\n',
}


def _scan(files: dict[str, str]) -> dict[str, set[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        for name, code in files.items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="\n") as f:
                f.write(code)
        out = subprocess.run(
            [SEMGREP, "--config", CHECKOP_RULES_DIR, "--json", "--quiet", "--metrics=off", tmp],
            capture_output=True, text=True, encoding="utf-8", timeout=180,
        )
        data = json.loads(out.stdout or "{}")
        assert not data.get("errors"), data.get("errors")
        found: dict[str, set[str]] = {}
        for r in data.get("results", []):
            found.setdefault(os.path.basename(r["path"]), set()).add(r["check_id"].split(".")[-1])
        return found


class RelativePathTest(unittest.TestCase):
    def test_caminho_sempre_com_barra_normal(self):
        # regressão: no Windows vinha ".github\workflows\ci.yml" e não casava com o nome enviado
        from app.sast_runner import _relative_to
        self.assertEqual(_relative_to(r"C:\tmp\x\.github\workflows\ci.yml", r"C:\tmp\x"), ".github/workflows/ci.yml")
        self.assertEqual(_relative_to("/tmp/x/src/app.py", "/tmp/x"), "src/app.py")


@unittest.skipUnless(SEMGREP, "Semgrep não instalado")
class CheckopRulesTest(unittest.TestCase):
    def test_regras_locais_entram_na_analise(self):
        self.assertIn(CHECKOP_RULES_DIR, SAST_RULESETS)

    def test_cada_regra_pega_a_falha(self):
        found = _scan({name: code for name, (code, _) in VULNERABLE.items()})
        for name, (_, expected) in VULNERABLE.items():
            self.assertTrue(expected <= found.get(name, set()), f"{name}: esperado {expected}, veio {found.get(name)}")

    def test_codigo_seguro_nao_dispara(self):
        self.assertEqual(_scan(SAFE), {})


if __name__ == "__main__":
    unittest.main()
