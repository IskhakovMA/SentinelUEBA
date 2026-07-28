import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { resetApiForTests } from './api';

const token = 'secret-control-token';

beforeEach(() => {
  resetApiForTests();
  vi.restoreAllMocks();
  vi.spyOn(Storage.prototype, 'setItem');
});

afterEach(() => {
  cleanup();
});

describe('SentinelUEBA dashboard', () => {
  it('shows Overview guided flow and calls synthetic generation with the control token', async () => {
    const fetchMock = mockFetch();
    render(<App />);
    expect(await screen.findByTestId('guided-flow')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /1\. Generate synthetic demo/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/demo/generate',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({}),
        }),
      );
    });
    const generateCall = fetchMock.mock.calls.find(([url]) => url === '/api/demo/generate');
    const headers = generateCall?.[1]?.headers as Headers;
    expect(headers.get('X-SentinelUEBA-Control-Token')).toBe(token);
  });

  it('renders loading, error and empty states with retry actions', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('offline'));
    render(<App />);
    expect(screen.getByText(/Loading SentinelUEBA state/i)).toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent(/offline/i);
    expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
  });

  it('disables Telemetry collection controls in service mode', async () => {
    mockFetch({ serviceMode: true });
    render(<App />);
    await openPage('Telemetry');

    expect(screen.getByTestId('service-mode-restriction')).toHaveTextContent(/service mode/i);
    expect(screen.getByRole('button', { name: /Start/i })).toBeDisabled();
  });

  it('shows training eligibility and asks for champion promotion confirmation', async () => {
    mockFetch();
    render(<App />);
    await openPage('ML Lab');

    expect(screen.getByText('Eligibility')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Promote$/i }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent(/Promote champion/i);
    expect(within(dialog).getByRole('button', { name: /^Promote$/i })).toBeInTheDocument();
  });

  it('runs Detection dry-run through the existing API contract', async () => {
    const fetchMock = mockFetch();
    render(<App />);
    await openPage('Detection Center');

    fireEvent.click(screen.getByRole('button', { name: /Dry-run/i }));

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([url]) => url === '/api/detection/run-once');
      expect(call).toBeTruthy();
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ dry_run: true });
    });
  });

  it('supports finding lifecycle and suppression create/revoke confirmations', async () => {
    mockFetch();
    render(<App />);
    await openPage('Findings');

    fireEvent.click(screen.getByRole('button', { name: /rare-process-v1/i }));
    expect(await screen.findByText(/Suspicious process/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Acknowledge/i }));
    const acknowledgeDialog = await screen.findByRole('dialog');
    expect(acknowledgeDialog).toHaveTextContent(/acknowledge finding/i);
    fireEvent.click(within(acknowledgeDialog).getByRole('button', { name: /^acknowledge$/i }));

    await waitFor(() =>
      expect(globalThis.fetch).toHaveBeenCalledWith(
        '/api/detection/findings/finding-1/acknowledge',
        expect.any(Object),
      ),
    );

    fireEvent.click(screen.getByRole('button', { name: /Create suppression/i }));
    expect(await screen.findByRole('dialog')).toHaveTextContent(/Create suppression/i);
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Create suppression/i }));

    await waitFor(() =>
      expect(globalThis.fetch).toHaveBeenCalledWith('/api/detection/suppressions', expect.any(Object)),
    );

    fireEvent.click(screen.getByRole('button', { name: /Revoke/i }));
    expect(await screen.findByRole('dialog')).toHaveTextContent(/Revoke suppression/i);
  });

  it('shows Runtime build and verification without leaking token or local identity', async () => {
    mockFetch();
    render(<App />);
    await openPage('Runtime');

    expect(screen.getAllByText(/0.6.0/i).length).toBeGreaterThan(0);
    expect(await screen.findByText(/unsigned technical preview/i)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(token);
    expect(document.body).not.toHaveTextContent('/Users/');
    expect(localStorage.setItem).not.toHaveBeenCalled();
  });

  it('requires confirmation for destructive dashboard actions', async () => {
    mockFetch();
    render(<App />);
    await openPage('Data Pipeline');

    fireEvent.click(screen.getByRole('button', { name: /Apply with confirmation/i }));

    expect(await screen.findByRole('dialog')).toHaveTextContent(/Apply retention policy/i);
  });
});

async function openPage(name: string) {
  await waitFor(() =>
    expect(screen.queryByText(/Loading SentinelUEBA state/i)).not.toBeInTheDocument(),
  );
  fireEvent.click(await screen.findByRole('button', { name }));
  await waitFor(() => expect(screen.getByRole('heading', { name, level: 1 })).toBeInTheDocument());
}

function mockFetch(options: { serviceMode?: boolean } = {}) {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input).replace('/api', '');
    const method = (init?.method ?? 'GET').toUpperCase();
    if (method !== 'GET' && url !== '/runtime/bootstrap') {
      const headers = init?.headers as Headers;
      if (headers?.get('X-SentinelUEBA-Control-Token') !== token) {
        return json({ detail: 'control token is required' }, 403);
      }
    }
    return route(url, method, options);
  });
  return fetchMock;
}

function route(url: string, method: string, options: { serviceMode?: boolean }) {
  if (url === '/runtime/bootstrap') {
    return json({ data: { version: '0.6.0', mode: options.serviceMode ? 'service' : 'desktop', service_mode: Boolean(options.serviceMode), control_token: token } });
  }
  if (url === '/health/ready') return json({ data: { ready: true, state: 'ready', mode: 'desktop', frontend_ready: true, database_ready: true, data_root_writable: true } });
  if (url === '/runtime/status') return json({ data: { state: 'ready', mode: options.serviceMode ? 'service' : 'desktop', version: '0.6.0' } });
  if (url === '/runtime/build') return json({ data: { version: '0.6.0', git_commit: 'abc123456789', build_timestamp_utc: '2026-07-28T12:00:00Z', mode: 'packaged', signed: false, frontend_build_hash: 'front-hash', release_manifest_sha256: 'manifest-hash' } });
  if (url === '/runtime/verify-installation') return json({ data: { status: 'unsigned_verified', signed: false, manifest_sha256: 'manifest-hash', checked_files: 42, errors: [] } });
  if (url === '/runtime/doctor') return json({ data: { status: 'healthy', schema_version: 10, mode: 'desktop', checks: [] } });
  if (url === '/status') return json({ data: baseStatus(options.serviceMode) });
  if (url === '/collectors/capabilities') return json({ data: { collectors: [{ collector_id: 'windows.process.psutil', status: 'available', required_privilege: 'user', errors: [] }] } });
  if (url === '/collection/sessions') return json({ data: { sessions: [] } });
  if (url === '/data-quality') return json({ data: quality() });
  if (url === '/retention/preview') return json({ data: { status: 'ready', would_delete: { telemetry_events: 0 } } });
  if (url === '/training/eligibility') return json({ data: { eligible: true, dataset_kind: 'synthetic', reasons: [] } });
  if (url === '/ml/status') return json({ data: mlStatus() });
  if (url === '/detection/status') return json({ data: detectionStatus() });
  if (url === '/detection/policies') return json({ data: { policies: [{ policy_id: 'hybrid-policy-v1', policy_version: '1', policy_hash: 'policy-hash', mode: 'hybrid', active: true }] } });
  if (url === '/detection/rules') return json({ data: { rules: [{ rule_id: 'rare-process-v1', enabled: true, severity: 'high' }] } });
  if (url.startsWith('/detection/findings/finding-1') && method === 'GET') return json({ data: findingDetail() });
  if (url.startsWith('/detection/findings?')) return json({ data: { findings: [finding()] } });
  if (url === '/detection/suppressions') return json({ data: { suppressions: [{ suppression_id: 'supp-1', scope: 'signal_for_dataset_kind', dataset_kind: 'synthetic', signal_id: 'rare-process-v1', reason: 'test', expires_at: '2026-07-28T13:00:00Z' }] } });
  return json({ data: { status: 'success', evaluated_count: 1, finding_count: 1, no_op_count: 0 } });
}

function baseStatus(serviceMode = false) {
  return {
    storage: { event_count: 120, anomaly_count: 0, quarantine_count: 0, feature_window_count: 96, model_count: 2, scoring_run_count: 1 },
    model: { trained: true, model_version: 'stage3' },
    collection: {
      running: false,
      session_id: null,
      collectors: {},
      counters: {},
      errors: [],
      progress: { cumulative_collected_seconds: 300, longest_continuous_session_seconds: 120, current_session_seconds: 0, progress_to_24h: 0.03, strict_continuous_24h_validated: false },
      event_summary: { real: {}, synthetic: { process: 40, network: 40, system_metrics: 40 } },
    },
    detection: detectionStatus(),
    data_pipeline: { features: { windows: { synthetic: { good: 96 }, real: {} } } },
    service_mode: serviceMode,
  };
}

function quality() {
  return {
    quarantine: { count: 0 },
    window_quality: { synthetic: { good: 96 }, real: {} },
    usable_coverage_seconds: 0,
    readiness: { synthetic_snapshot: true, real_snapshot: false },
    watermark: { synthetic: '2026-07-28T12:00:00Z', real: null },
    dataset_snapshots: { synthetic: [{ dataset_id: 'dataset-1', manifest_sha256: 'manifest-1', created_at: '2026-07-28T12:00:00Z', verified_at: '2026-07-28T12:01:00Z' }], real: [] },
    collection_progress: { cumulative_collected_seconds: 300, longest_continuous_session_seconds: 120, current_session_seconds: 0, progress_to_24h: 0.03, strict_continuous_24h_validated: false },
  };
}

function mlStatus() {
  return {
    schema_version: 10,
    legacy_unregistered: false,
    champions: [],
    models: [{ model_id: 'model-1', family: 'autoencoder', model_version: 'autoencoder-v2', lifecycle_status: 'recommended', dataset_id: 'dataset-1', dataset_kind: 'synthetic', threshold: 0.42, created_at: '2026-07-28T12:00:00Z' }],
    training_runs: [],
    scoring_runs: [],
  };
}

function detectionStatus() {
  return {
    schema_version: 10,
    active_policy: { policy_id: 'hybrid-policy-v1', policy_version: '1', policy_hash: 'policy-hash', mode: 'hybrid', finding_threshold: 0.7, fusion_method: 'hybrid-fusion-v1', rules: [{ rule_id: 'rare-process-v1', enabled: true }] },
    latest_run: { status: 'success', mode: 'once', evaluated_count: 96, skipped_count: 0, finding_count: 1, no_op_count: 0 },
    finding_counts: { open: 1 },
    evaluation_count: 96,
    watermarks: [],
    worker: { status: 'stopped' },
  };
}

function finding() {
  return {
    finding_id: 'finding-1',
    fingerprint: 'finding-fingerprint-v2-value',
    dataset_kind: 'synthetic',
    profile_key: 'profile-secret',
    status: 'open',
    risk_level: 'high',
    detection_score: 0.91,
    primary_signal_id: 'rare-process-v1',
    title: 'Suspicious process behavior',
    summary: 'Human-readable synthetic finding summary.',
    first_seen_at: '2026-07-28T12:00:00Z',
    last_seen_at: '2026-07-28T12:15:00Z',
    occurrence_count: 2,
  };
}

function findingDetail() {
  return {
    ...finding(),
    occurrences: [{ occurrence_id: 'occ-1', detection_run_id: 'run-1', window_id: 'win-1', window_start: '2026-07-28T12:00:00Z', status: 'finding', matched_signal_ids: ['rare-process-v1'], decision: { score: 0.91, threshold: 0.7 } }],
    history: [{ history_id: 'hist-1', from_status: 'new', to_status: 'open', reason: 'created', created_at: '2026-07-28T12:00:00Z' }],
  };
}

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
}
