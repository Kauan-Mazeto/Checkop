import { updateNucleiTemplates } from './py/security_engine_client.js';

// RF-45 - mantém a base de templates do Nuclei atualizada (CVEs novas).
// Roda sozinha a cada NUCLEI_TEMPLATE_UPDATE_HOURS (padrão 24; 0 desliga) e
// pode ser disparada por um administrador. O estado fica em memória: depois de
// reiniciar o servidor, "última atualização" volta a vazio até a próxima rodada.

const state = { running: false, lastRunAt: null, lastSuccessAt: null, lastError: null };

export const templateUpdateStatus = () => ({ ...state });

export const runTemplateUpdate = async () => {
  if (state.running) return { started: false, ...templateUpdateStatus() };
  state.running = true;
  state.lastRunAt = new Date();
  try {
    await updateNucleiTemplates();
    state.lastSuccessAt = new Date();
    state.lastError = null;
  } catch (error) {
    state.lastError = error.message;
    console.error('[templates] falha ao atualizar os templates do Nuclei:', error.message);
  } finally {
    state.running = false;
  }
  return { started: true, ...templateUpdateStatus() };
};

const ONE_HOUR_MS = 60 * 60 * 1000;

export const scheduleTemplateUpdates = () => {
  const hours = Number(process.env.NUCLEI_TEMPLATE_UPDATE_HOURS ?? 24);
  if (!Number.isFinite(hours) || hours <= 0) return null;
  // primeira rodada alguns minutos depois de subir, para não atrasar a inicialização
  const first = setTimeout(runTemplateUpdate, 5 * 60 * 1000);
  const every = setInterval(runTemplateUpdate, hours * ONE_HOUR_MS);
  first.unref();
  every.unref();
  return every;
};

/** Só para testes. */
export const resetTemplateUpdateState = () => {
  Object.assign(state, { running: false, lastRunAt: null, lastSuccessAt: null, lastError: null });
};
