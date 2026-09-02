// startAppliance runs a second scan2graph, because the harness's own cannot
// be configured two ways at once. args and env are exactly what the caller
// passes - nothing is quietly filled in here - and stderr is kept, because
// "it would not start" is a failure a test has to be able to explain.

import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect } from '@playwright/test';

const e2e = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export function startAppliance({ args, env, smtpPort }) {
  const child = spawn(path.join(e2e, '.bin', 'scan2graph'), args, {
    stdio: ['ignore', 'ignore', 'pipe'],
    env,
  });
  const started = { child, log: '', exited: false, smtpPort };
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    started.log += chunk;
  });
  child.once('exit', (code) => {
    started.exited = true;
    started.log += `\nthe appliance exited with code ${code}`;
  });
  return started;
}

// serving waits until the scan can actually be sent: the SMTP listener binds
// on a goroutine of its own, so the process being up is not the same thing.
export async function serving(a) {
  await expect(async () => {
    expect(a.exited, a.log).toBe(false);
    await new Promise((resolve, reject) => {
      const socket = createConnection({ host: '127.0.0.1', port: a.smtpPort });
      socket.once('connect', () => {
        socket.end();
        resolve();
      });
      socket.once('error', reject);
    });
  }).toPass({ intervals: [50], timeout: 30_000 });
}
