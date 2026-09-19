import axios from 'axios';

const api = axios.create({ baseURL: 'https://adaptive-universal-pre-procession-logger.onrender.com/api' });

export const processEvent = (raw_message: string, source = 'manual') =>
  api.post('/events/process', { raw_message, source });

export const processEvents = (events: Array<{raw_message: string, source?: string}>) =>
  api.post('/events/batch', { events });

export const getEvents = (limit = 50) => api.get(`/events?limit=${limit}`);
export const getEvent = (id: string) => api.get(`/events/${id}`);
export const getParsers = () => api.get('/parsers');
export const getParser = (id: string) => api.get(`/parsers/${id}`);
export const promoteParser = (id: string) => api.post(`/parsers/${id}/promote`);
export const approveParser = (id: string) => api.post(`/parsers/${id}/approve`);
export const rollbackParser = (id: string) => api.post(`/parsers/${id}/rollback`);
export const getQuarantine = () => api.get('/quarantine');
export const reprocessQuarantine = (id: string) => api.post(`/quarantine/${id}/reprocess`);
export const discardQuarantine = (id: string) => api.post(`/quarantine/${id}/discard`);
export const approveQuarantine = (id: string) => api.post(`/quarantine/${id}/approve`);
export const reviewQuarantine = (id: string) => api.post(`/quarantine/${id}/review`);
export const verifyIntegrity = () => api.post('/integrity/verify');
export const commitToLedger = () => api.post('/integrity/commit');
export const getLedger = () => api.get('/integrity/ledger');
export const tamperDemo = () => api.post('/integrity/tamper-demo');
export const getMetrics = () => api.get('/metrics');
export const getHealth = () => api.get('/health');
export const runBenchmark = (count = 100) => api.post(`/benchmark/run?event_count=${count}`);
export const getBenchmarkResults = () => api.get('/benchmark/results');
export const executeDemoStep = (step: number) => api.post(`/demo/step/${step}`);
export const resetDemo = () => api.post('/demo/reset');
export const getDemoState = () => api.get('/demo/state');

// Plug-and-Play Onboarding
export const getOnboardingSamples = () => api.get('/onboarding/samples');
export const profileSource = (source_name: string, sample_logs: string[]) =>
  api.post('/onboarding/profile', { source_name, sample_logs });
export const promoteOnboardedParser = (candidate_id: string) =>
  api.post(`/onboarding/promote/${candidate_id}`);
