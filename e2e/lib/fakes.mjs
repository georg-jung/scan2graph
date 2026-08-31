// Wrappers over the fakes' /inspect API: what the appliance actually sent to
// Document Intelligence and to Graph, and the switch that makes OCR fail.

const INSPECT = 'http://127.0.0.1:19000/inspect';

// The one fixture credential in the suite: SMTP password and Entra client
// secret alike. A single obviously-fake constant, so a secret scanner has
// nothing to find and no test invents a literal of its own.
export const FIXTURE_SECRET = 'fixture-not-a-real-secret';

export const resetFakes = () => post('/reset');
export const setDIMode = (mode) => post('/di/mode', JSON.stringify({ mode }));

// diSubmissions is every analyze *attempt* the appliance made, in order:
// {sha256, size}. A failing analyze appears several times because the client
// retries, so assert on the digests, never on the count.
export const diSubmissions = async () => (await get('/di')).submissions;
export const graphMessages = async () => (await get('/graph')).messages;

async function get(path) {
  const res = await fetch(INSPECT + path);
  if (!res.ok) throw new Error(`GET ${INSPECT}${path}: HTTP ${res.status}`);
  return res.json();
}

async function post(path, body) {
  const res = await fetch(INSPECT + path, { method: 'POST', body });
  if (!res.ok) throw new Error(`POST ${INSPECT}${path}: HTTP ${res.status}`);
}
