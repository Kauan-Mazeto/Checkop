import { createHash } from 'node:crypto';
import prisma from './prisma.js';
import { translateTexts } from './py/security_engine_client.js';
import { SOURCE_LANGUAGE } from '../constants/languages.js';

// O ZAP e o Nuclei publicam as regras em inglês. Os achados são gravados no
// original e traduzidos na leitura, no idioma do usuário: trocar o idioma vale
// também para as varreduras antigas. Achados do Subfinder já são escritos em
// português pelo próprio Checkop e não passam pela tradução.
const TRANSLATED_TOOLS = new Set(['ZAP', 'NUCLEI']);
const TRANSLATED_FIELDS = ['title', 'description', 'remediation', 'detection'];

export const sourceHash = (text) => createHash('sha256').update(text).digest('hex');

const isSourceLanguage = (language) => language.split('-')[0] === SOURCE_LANGUAGE;

const translatableTexts = (findings) => {
  const texts = new Set();
  for (const finding of findings) {
    if (!TRANSLATED_TOOLS.has(finding.tool)) continue;
    for (const field of TRANSLATED_FIELDS) {
      const value = finding[field];
      if (typeof value === 'string' && value.trim()) texts.add(value);
    }
  }
  return [...texts];
};

const readCache = async (texts, language) => {
  const byHash = new Map(texts.map((text) => [sourceHash(text), text]));
  const rows = await prisma.translationCache.findMany({
    where: { language, sourceHash: { in: [...byHash.keys()] } },
  });
  return new Map(rows.map((row) => [byHash.get(row.sourceHash), row.text]));
};

const writeCache = (entries, language) =>
  Promise.all(
    entries.map(([original, text]) =>
      prisma.translationCache.upsert({
        where: { language_sourceHash: { language, sourceHash: sourceHash(original) } },
        create: { language, sourceHash: sourceHash(original), text },
        update: { text },
      }),
    ),
  );

/**
 * Devolve os achados com título, descrição e correção no idioma pedido.
 * Nunca falha: sem motor ou sem cota de tradução, o texto original é mantido.
 */
// o auth_middleware sempre preenche o idioma (padrão do banco: pt-BR);
// sem idioma informado não há o que traduzir
export const translateFindings = async (findings, language) => {
  if (!language || isSourceLanguage(language) || findings.length === 0) return findings;

  const texts = translatableTexts(findings);
  if (texts.length === 0) return findings;

  let translated = new Map();
  try {
    translated = await readCache(texts, language);
  } catch (error) {
    console.error('Erro ao ler o cache de traduções:', error.message);
  }

  const missing = texts.filter((text) => !translated.has(text));
  if (missing.length > 0) {
    try {
      const result = await translateTexts(missing, language);
      // o motor devolve o original quando não consegue traduzir: isso não vai para o cache
      const fresh = missing
        .filter((text) => typeof result[text] === 'string' && result[text].trim() && result[text] !== text)
        .map((text) => [text, result[text]]);
      for (const [original, text] of fresh) translated.set(original, text);
      await writeCache(fresh, language);
    } catch (error) {
      console.warn(`Tradução para ${language} indisponível agora: ${error.message}`);
    }
  }

  if (translated.size === 0) return findings;

  return findings.map((finding) => {
    if (!TRANSLATED_TOOLS.has(finding.tool)) return finding;
    const copy = { ...finding };
    for (const field of TRANSLATED_FIELDS) {
      if (typeof copy[field] === 'string' && translated.has(copy[field])) copy[field] = translated.get(copy[field]);
    }
    return copy;
  });
};

/**
 * Traduz os achados de uma varredura recém-terminada para o idioma do dono,
 * antes de ela aparecer como concluída: ao abrir a página, o texto já está no
 * cache. Nunca falha (sem tradução, a página traduz ou mostra o original).
 */
export const warmTranslations = async (findings, userId) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { language: true } });
    if (user?.language) await translateFindings(findings, user.language);
  } catch (error) {
    console.warn('Pré-tradução dos achados ignorada:', error.message);
  }
};
