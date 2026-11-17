// Idiomas oferecidos para os textos dos achados (título, descrição, correção).
// As regras do ZAP e do Nuclei são publicadas em inglês; os demais idiomas são
// traduzidos pelo motor (DeepL com chave, MyMemory sem chave).
export const LANGUAGES = [
  { code: 'pt-BR', label: 'Português (Brasil)' },
  { code: 'en', label: 'English (original)' },
  { code: 'es', label: 'Español' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
  { code: 'it', label: 'Italiano' },
  { code: 'nl', label: 'Nederlands' },
  { code: 'pl', label: 'Polski' },
  { code: 'ru', label: 'Русский' },
  { code: 'uk', label: 'Українська' },
  { code: 'tr', label: 'Türkçe' },
  { code: 'ja', label: '日本語' },
  { code: 'ko', label: '한국어' },
  { code: 'zh-CN', label: '中文 (简体)' },
];

export const DEFAULT_LANGUAGE = 'pt-BR';
export const SOURCE_LANGUAGE = 'en';
export const LANGUAGE_CODES = LANGUAGES.map((language) => language.code);
