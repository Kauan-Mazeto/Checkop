// Espelha backend/src/constants/languages.js. Só os textos dos achados
// (título, descrição, correção) mudam de idioma; a interface segue em português.
export interface LanguageOption {
  code: string;
  label: string;
}

export const LANGUAGES: readonly LanguageOption[] = [
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
