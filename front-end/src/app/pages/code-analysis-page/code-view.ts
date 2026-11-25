export interface CodeLine {
  number: number;
  text: string;
  vulnerable: boolean;
}

/**
 * Recorte "estilo IDE" do arquivo em volta das linhas vulneráveis
 * (espec.txt 3.2: visualizador com a linha crítica destacada).
 */
export const buildCodeView = (content: string, start: number, end: number, context = 4): CodeLine[] => {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  const first = Math.max(1, start - context);
  const last = Math.min(lines.length, end + context);
  const view: CodeLine[] = [];
  for (let n = first; n <= last; n++) {
    view.push({ number: n, text: lines[n - 1] ?? '', vulnerable: n >= start && n <= end });
  }
  return view;
};

// Extensões aceitas: tudo que o Semgrep analisa com regras de segurança
// (pacotes oficiais + regras próprias do Checkop em rules/checkop).
export const ACCEPTED_EXTENSIONS = [
  // web e back-end
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.html', '.htm', '.py', '.php', '.rb', '.go',
  // JVM e .NET
  '.java', '.kt', '.kts', '.scala', '.cs',
  // sistemas e mobile
  '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.rs', '.swift',
  // scripts, infraestrutura e configuração
  '.sh', '.bash', '.zsh', '.tf', '.hcl', '.yaml', '.yml', '.json', '.dockerfile',
  // outras com regras no registro
  '.cls', '.ml', '.sol',
];

/** Arquivos reconhecidos pelo nome (sem extensão). */
export const ACCEPTED_FILENAMES = [
  'dockerfile', 'containerfile',
  // dependências (OSV-Scanner)
  'requirements.txt', 'pipfile.lock', 'poetry.lock', 'pdm.lock', 'uv.lock', 'package-lock.json', 'yarn.lock',
  'pnpm-lock.yaml', 'go.mod', 'go.sum', 'pom.xml', 'gradle.lockfile', 'composer.lock', 'gemfile.lock',
  'cargo.lock', 'packages.lock.json', 'pubspec.lock', 'mix.lock',
];

export const isAcceptedFile = (name: string): boolean => {
  const lower = name.toLowerCase();
  const base = lower.split(/[\\/]/).pop() ?? lower;
  return ACCEPTED_FILENAMES.includes(base) || base.startsWith('dockerfile.') || ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
};

export type LanguageGroup = 'Web e back-end' | 'JVM e .NET' | 'Sistemas e mobile' | 'Infraestrutura e scripts' | 'Dependências';

export interface CodeLanguage {
  label: string;
  group: LanguageGroup;
  /** a extensão (ou o nome, no Dockerfile) orienta quais regras o Semgrep aplica */
  filename: string;
  /** exemplo didático vulnerável, conferido contra a análise do Checkop */
  example: string;
}

export const LANGUAGE_GROUPS: LanguageGroup[] = ['Web e back-end', 'JVM e .NET', 'Sistemas e mobile', 'Infraestrutura e scripts', 'Dependências'];

export const LANGUAGES: CodeLanguage[] = [
  {
    label: 'JavaScript (Node.js + Sequelize)',
    group: 'Web e back-end',
    filename: 'app.js',
    example: [
      "const express = require('express');",
      "const { Sequelize } = require('sequelize');",
      'const app = express();',
      "const sequelize = new Sequelize('sqlite::memory:');",
      '',
      "app.get('/usuarios', async (req, res) => {",
      '  // a entrada do usuário é concatenada direto na consulta',
      "  const rows = await sequelize.query(\"SELECT * FROM usuarios WHERE nome = '\" + req.query.nome + \"'\");",
      '  res.json(rows);',
      '});',
    ].join('\n'),
  },
  {
    label: 'TypeScript (Express)',
    group: 'Web e back-end',
    filename: 'app.ts',
    example: [
      "import express from 'express';",
      "import { exec } from 'child_process';",
      '',
      'const app = express();',
      '',
      "app.get('/listar', (req, res) => {",
      '  // o parâmetro vira parte de um comando de shell',
      '  exec(`ls ${req.query.pasta}`, (err, saida) => res.send(saida));',
      '});',
      '',
      "app.get('/sair', (req, res) => {",
      '  res.redirect(req.query.voltar as string);',
      '});',
    ].join('\n'),
  },
  {
    label: 'Python (Flask + sqlite3)',
    group: 'Web e back-end',
    filename: 'app.py',
    example: [
      'import sqlite3',
      'from flask import Flask, request',
      '',
      'app = Flask(__name__)',
      '',
      '@app.route("/usuario")',
      'def usuario():',
      '    user_id = request.args.get("id")',
      '    conn = sqlite3.connect("app.db")',
      '    cursor = conn.cursor()',
      '    cursor.execute("SELECT * FROM usuarios WHERE id = \'%s\'" % user_id)',
      '    return str(cursor.fetchall())',
    ].join('\n'),
  },
  {
    label: 'PHP (mysqli)',
    group: 'Web e back-end',
    filename: 'login.php',
    example: [
      '<?php',
      '$conn = mysqli_connect("localhost", "root", "", "loja");',
      "$usuario = $_GET['usuario'];",
      "$resultado = mysqli_query($conn, \"SELECT * FROM usuarios WHERE nome = '\" . $usuario . \"'\");",
      "include($_GET['pagina']);",
      "$hash = md5($_POST['senha']);",
    ].join('\n'),
  },
  {
    label: 'Ruby (Sinatra)',
    group: 'Web e back-end',
    filename: 'app.rb',
    example: [
      "require 'sinatra'",
      '',
      "get '/ping' do",
      '  # o host vira parte de um comando de shell',
      '  `ping -c 1 #{params[:host]}`',
      'end',
      '',
      "get '/busca' do",
      "  User.where(\"nome = '#{params[:nome]}'\")",
      'end',
    ].join('\n'),
  },
  {
    label: 'Go (net/http)',
    group: 'Web e back-end',
    filename: 'main.go',
    example: [
      'package main',
      '',
      'import (',
      '\t"database/sql"',
      '\t"net/http"',
      '\t"os/exec"',
      ')',
      '',
      'var db *sql.DB',
      '',
      'func handler(w http.ResponseWriter, r *http.Request) {',
      '\tnome := r.URL.Query().Get("nome")',
      '\tdb.Query("SELECT * FROM usuarios WHERE nome = \'" + nome + "\'")',
      '\texec.Command("sh", "-c", "ping "+r.URL.Query().Get("host")).Run()',
      '}',
    ].join('\n'),
  },
  {
    label: 'HTML (JavaScript no navegador)',
    group: 'Web e back-end',
    filename: 'index.html',
    example: [
      '<html>',
      '<body>',
      '  <div id="saudacao"></div>',
      '  <a href="https://parceiro.com" target="_blank">Parceiro</a>',
      '  <script>',
      '    // o trecho depois do # na URL vira HTML na página',
      "    document.getElementById('saudacao').innerHTML = decodeURIComponent(location.hash.substring(1));",
      '  </script>',
      '</body>',
      '</html>',
    ].join('\n'),
  },
  {
    label: 'Java (Servlet + JDBC)',
    group: 'JVM e .NET',
    filename: 'Busca.java',
    example: [
      'import java.sql.*;',
      'import javax.servlet.http.*;',
      '',
      'public class Busca extends HttpServlet {',
      '    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {',
      '        String nome = req.getParameter("nome");',
      '        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/loja");',
      '        Statement st = conn.createStatement();',
      '        ResultSet rs = st.executeQuery("SELECT * FROM clientes WHERE nome = \'" + nome + "\'");',
      '    }',
      '}',
    ].join('\n'),
  },
  {
    label: 'Kotlin (JDBC)',
    group: 'JVM e .NET',
    filename: 'Busca.kt',
    example: [
      'import java.sql.DriverManager',
      'import javax.servlet.http.HttpServletRequest',
      '',
      'fun busca(req: HttpServletRequest) {',
      '    val nome = req.getParameter("nome")',
      '    val conn = DriverManager.getConnection("jdbc:mysql://localhost/loja")',
      '    conn.createStatement().executeQuery("SELECT * FROM clientes WHERE nome = \'" + nome + "\'")',
      '    Runtime.getRuntime().exec("ping " + req.getParameter("host"))',
      '}',
    ].join('\n'),
  },
  {
    label: 'Scala',
    group: 'JVM e .NET',
    filename: 'Ping.scala',
    example: [
      'import scala.sys.process._',
      '',
      'object Ping {',
      '  // o host vira parte do comando executado',
      '  def ping(host: String): String = s"ping -c 1 $host".!!',
      '}',
    ].join('\n'),
  },
  {
    label: 'C# (ASP.NET)',
    group: 'JVM e .NET',
    filename: 'HomeController.cs',
    example: [
      'using System.Data.SqlClient;',
      'using System.Diagnostics;',
      'using Microsoft.AspNetCore.Mvc;',
      '',
      'public class HomeController : Controller',
      '{',
      '    public IActionResult Busca(string nome)',
      '    {',
      '        var conn = new SqlConnection("Server=.;Database=loja;User Id=sa;Password=senha123;");',
      '        var cmd = new SqlCommand("SELECT * FROM clientes WHERE nome = \'" + nome + "\'", conn);',
      '        Process.Start("cmd.exe", "/c ping " + nome);',
      '        return Content("<p>Olá " + nome + "</p>", "text/html");',
      '    }',
      '}',
    ].join('\n'),
  },
  {
    label: 'C',
    group: 'Sistemas e mobile',
    filename: 'main.c',
    example: [
      '#include <stdio.h>',
      '#include <string.h>',
      '#include <stdlib.h>',
      '',
      'int main(int argc, char **argv) {',
      '    char nome[16];',
      '    strcpy(nome, argv[1]);      /* sem limite de tamanho */',
      '    printf(argv[1]);            /* entrada usada como formato */',
      '    char cmd[64];',
      '    sprintf(cmd, "ping %s", argv[1]);',
      '    system(cmd);',
      '    return 0;',
      '}',
    ].join('\n'),
  },
  {
    label: 'Rust',
    group: 'Sistemas e mobile',
    filename: 'main.rs',
    example: [
      'use std::process::Command;',
      '',
      'fn ping(host: &str) {',
      '    // o host vira parte de um comando de shell',
      '    Command::new("sh")',
      '        .arg("-c")',
      '        .arg(format!("ping -c 1 {}", host))',
      '        .output()',
      '        .unwrap();',
      '}',
    ].join('\n'),
  },
  {
    label: 'Swift (iOS)',
    group: 'Sistemas e mobile',
    filename: 'Sessao.swift',
    example: [
      'import Foundation',
      '',
      'func salvarSessao(token: String) {',
      '    // UserDefaults fica em texto puro no aparelho',
      '    UserDefaults.standard.set(token, forKey: "authToken")',
      '}',
    ].join('\n'),
  },
  {
    label: 'Shell (Bash)',
    group: 'Infraestrutura e scripts',
    filename: 'deploy.sh',
    example: [
      '#!/bin/bash',
      '# instala a ferramenta direto da internet',
      'curl -k https://exemplo.com/install.sh | bash',
      'eval "$1"',
      'chmod 777 /var/www',
    ].join('\n'),
  },
  {
    label: 'Dockerfile',
    group: 'Infraestrutura e scripts',
    filename: 'Dockerfile',
    example: [
      'FROM node:latest',
      'USER root',
      'ADD https://exemplo.com/app.tar.gz /app',
      'ENV DB_PASSWORD=senha123',
      'RUN curl http://exemplo.com/setup.sh | sh',
      'CMD ["node", "/app/server.js"]',
    ].join('\n'),
  },
  {
    label: 'Terraform (AWS)',
    group: 'Infraestrutura e scripts',
    filename: 'main.tf',
    example: [
      'resource "aws_s3_bucket" "dados" {',
      '  bucket = "dados-clientes"',
      '  acl    = "public-read"',
      '}',
      '',
      'resource "aws_security_group" "web" {',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
    ].join('\n'),
  },
  {
    label: 'Kubernetes (YAML)',
    group: 'Infraestrutura e scripts',
    filename: 'deployment.yaml',
    example: [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'metadata:',
      '  name: app',
      'spec:',
      '  template:',
      '    spec:',
      '      containers:',
      '        - name: app',
      '          image: app:latest',
      '          securityContext:',
      '            privileged: true',
      '            allowPrivilegeEscalation: true',
    ].join('\n'),
  },
  {
    label: 'GitHub Actions',
    group: 'Infraestrutura e scripts',
    filename: '.github/workflows/ci.yml',
    example: [
      'on: pull_request_target',
      'jobs:',
      '  build:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      '      - run: echo "${{ github.event.pull_request.title }}"',
    ].join('\n'),
  },
  {
    label: 'Python (requirements.txt)',
    group: 'Dependências',
    filename: 'requirements.txt',
    example: [
      '# versões antigas com vulnerabilidades conhecidas (CVE)',
      'django==2.2.0',
      'requests==2.19.1',
      'pyyaml==5.3',
      'flask==0.12.2',
      'jinja2==2.10',
    ].join('\n'),
  },
  {
    label: 'Go (go.mod)',
    group: 'Dependências',
    filename: 'go.mod',
    example: [
      'module exemplo.com/loja',
      '',
      'go 1.21',
      '',
      'require (',
      '\tgithub.com/gin-gonic/gin v1.6.0',
      '\tgolang.org/x/crypto v0.0.0-20200622213623-75b288015ac9',
      '\tgithub.com/dgrijalva/jwt-go v3.2.0+incompatible',
      ')',
    ].join('\n'),
  },
];

// ---------- diff lado a lado (correção com IA, espec.txt 3.2) ----------

export interface DiffCell {
  number: number;
  text: string;
  /** linha removida (esquerda) ou adicionada (direita) */
  changed: boolean;
}

export interface DiffRow {
  left: DiffCell | null;
  right: DiffCell | null;
}

/**
 * Diff por linhas (LCS) em linhas pareadas: à esquerda o código original, à
 * direita o corrigido. Linhas trocadas ficam lado a lado na mesma altura.
 */
export const sideBySideDiff = (before: string, after: string, firstLine = 1): DiffRow[] => {
  const a = before.replace(/\r\n/g, '\n').split('\n');
  const b = after.replace(/\r\n/g, '\n').split('\n');
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const rows: DiffRow[] = [];
  let removed: DiffCell[] = [];
  let added: DiffCell[] = [];
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++) {
      rows.push({ left: removed[k] ?? null, right: added[k] ?? null });
    }
    removed = [];
    added = [];
  };

  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      flush();
      rows.push({
        left: { number: firstLine + i, text: a[i], changed: false },
        right: { number: firstLine + j, text: b[j], changed: false },
      });
      i++;
      j++;
    } else if (j < b.length && (i >= a.length || lcs[i][j + 1] >= lcs[i + 1][j])) {
      added.push({ number: firstLine + j, text: b[j], changed: true });
      j++;
    } else {
      removed.push({ number: firstLine + i, text: a[i], changed: true });
      i++;
    }
  }
  flush();
  return rows;
};

/** Janela de linhas em volta do achado: é o que vai para a IA (não o arquivo inteiro). */
export const codeWindow = (content: string, start: number, end: number, context = 8): { code: string; firstLine: number } => {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  const first = Math.max(1, start - context);
  const last = Math.min(lines.length, end + context);
  return { code: lines.slice(first - 1, last).join('\n'), firstLine: first };
};