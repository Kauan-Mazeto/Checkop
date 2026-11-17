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

// Extensões aceitas: as linguagens que o Semgrep (--config=auto) analisa com regras de segurança.
export const ACCEPTED_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.php', '.java', '.go', '.rb', '.cs',
  '.kt', '.scala', '.c', '.cpp', '.h', '.rs', '.swift', '.html', '.vue', '.json', '.yaml', '.yml', '.tf', '.sh',
];

export const isAcceptedFile = (name: string): boolean =>
  ACCEPTED_EXTENSIONS.some((ext) => name.toLowerCase().endsWith(ext));

export interface CodeLanguage {
  label: string;
  /** a extensão orienta quais regras o Semgrep aplica */
  filename: string;
  /** exemplo didático com SQL Injection, conferido contra o Semgrep (--config=auto) */
  example: string;
}

export const LANGUAGES: CodeLanguage[] = [
  {
    label: 'JavaScript (Node.js + Sequelize)',
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
    label: 'Python (Flask + sqlite3)',
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
    filename: 'login.php',
    example: [
      '<?php',
      '$conn = mysqli_connect("localhost", "root", "", "loja");',
      "$usuario = $_GET['usuario'];",
      "$resultado = mysqli_query($conn, \"SELECT * FROM usuarios WHERE nome = '\" . $usuario . \"'\");",
      'echo mysqli_num_rows($resultado);',
    ].join('\n'),
  },
  {
    label: 'Java (Servlet + JDBC)',
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
  { label: 'TypeScript', filename: 'app.ts', example: '' },
  { label: 'Go', filename: 'main.go', example: '' },
  { label: 'C#', filename: 'Program.cs', example: '' },
  { label: 'Ruby', filename: 'app.rb', example: '' },
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