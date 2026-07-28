import type { RuntimeBootstrap } from './types';

const CONTROL_HEADER = 'X-SentinelUEBA-Control-Token';

let bootstrapPromise: Promise<RuntimeBootstrap | null> | null = null;
let controlToken: string | null = null;

async function fetchBootstrap(force = false): Promise<RuntimeBootstrap | null> {
  if (force) {
    bootstrapPromise = null;
    controlToken = null;
  }
  if (!bootstrapPromise) {
    bootstrapPromise = fetch('/api/runtime/bootstrap')
      .then(async (response) => {
        if (!response.ok) return null;
        const payload = (await response.json()) as { data: RuntimeBootstrap };
        controlToken = payload.data.control_token ?? null;
        return payload.data;
      })
      .catch(() => null);
  }
  return bootstrapPromise;
}

export async function runtimeBootstrap(force = false): Promise<RuntimeBootstrap | null> {
  return fetchBootstrap(force);
}

export async function api<T>(path: string, options: RequestInit = {}, retried = false): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase();
  const headers = new Headers(options.headers);
  if (options.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    await fetchBootstrap(false);
    if (controlToken) {
      headers.set(CONTROL_HEADER, controlToken);
    }
  }
  const response = await fetch(`/api${path}`, { ...options, headers });
  if (response.status === 403 && !retried && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    await fetchBootstrap(true);
    return api<T>(path, options, true);
  }
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      if (typeof payload.detail === 'string') message = payload.detail;
    } catch {
      message = await response.text();
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}

export function resetApiForTests(): void {
  bootstrapPromise = null;
  controlToken = null;
}
