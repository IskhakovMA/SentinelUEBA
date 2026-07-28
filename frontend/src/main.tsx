import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  Archive,
  Bell,
  Database,
  Languages,
  Play,
  Radar,
  RefreshCw,
  Shield,
  Sparkles,
  Square,
} from 'lucide-react';
import './styles.css';

type Risk = 'low' | 'medium' | 'high' | 'critical';

type Anomaly = {
  timestamp: string;
  user_id: string;
  host_id: string;
  anomaly_score: number;
  threshold: number;
  risk_level: Risk;
  top_features: string[];
  explanation: string;
};

type Status = {
  storage: {
    event_count: number;
    anomaly_count: number;
    database_path: string;
    quarantine_count?: number;
    feature_window_count?: number;
    model_count?: number;
    scoring_run_count?: number;
  };
  model: { trained?: boolean; model_version?: string };
  collection?: CollectionStatus;
  data_pipeline?: DataPipelineStatus;
  detection?: DetectionStatus;
};

type Locale = 'en' | 'ru';

type RuntimeBootstrap = {
  version: string;
  mode: string;
  service_mode: boolean;
  control_token?: string | null;
};

type CollectorCapability = {
  collector_id: string;
  status: string;
  required_privilege: string;
  errors: string[];
};

type CollectionStatus = {
  running: boolean;
  session_id: string | null;
  collectors: Record<string, { status: string; errors: string[]; events_collected: number }>;
  counters: Record<string, number>;
  errors: string[];
  progress: {
    cumulative_collected_seconds: number;
    longest_continuous_session_seconds: number;
    current_session_seconds: number;
    progress_to_24h: number;
    strict_continuous_24h_validated: boolean;
  };
  event_summary?: { real?: Record<string, number>; synthetic?: Record<string, number> };
};

type DataQuality = {
  quarantine: { count: number };
  window_quality: Record<string, Record<string, number>>;
  usable_coverage_seconds: number;
  readiness: {
    synthetic_snapshot: boolean;
    real_snapshot: boolean;
    synthetic?: Record<string, unknown>;
    real?: Record<string, unknown>;
  };
  watermark: { synthetic?: string | null; real?: string | null };
  dataset_snapshots: {
    synthetic: Array<{ dataset_id: string; manifest_sha256: string; created_at: string }>;
    real: Array<{ dataset_id: string; manifest_sha256: string; created_at: string }>;
  };
  collection_progress: CollectionStatus['progress'];
};

type DataPipelineStatus = {
  quarantine: { count: number };
  features: {
    windows?: {
      synthetic?: Record<string, number>;
      real?: Record<string, number>;
    };
  };
  snapshots: DataQuality['dataset_snapshots'];
};

let runtimeBootstrapPromise: Promise<RuntimeBootstrap | null> | null = null;

async function runtimeBootstrap(): Promise<RuntimeBootstrap | null> {
  if (!runtimeBootstrapPromise) {
    runtimeBootstrapPromise = fetch('/api/runtime/bootstrap')
      .then(async (response) => {
        if (!response.ok) return null;
        const payload = (await response.json()) as { data: RuntimeBootstrap };
        return payload.data;
      })
      .catch(() => null);
  }
  return runtimeBootstrapPromise;
}

type ScenarioValidation = {
  scenario_name: string;
  detected: boolean;
  match_count?: number;
  best_anomaly_score: number;
  max_risk_level?: string;
};

type MLModel = {
  model_id: string;
  family: string;
  model_version: string;
  lifecycle_status: string;
  dataset_id: string;
  dataset_kind: string;
  threshold: number;
  created_at: string;
  verified_at?: string | null;
};

type MLTrainingRun = {
  training_run_id: string;
  dataset_id: string;
  dataset_kind: string;
  split_id: string;
  profile_key: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
  safe_error_message?: string | null;
};

type MLScoringRun = {
  scoring_run_id: string;
  model_id: string;
  dataset_id: string;
  split_range?: { kind?: string };
  status: string;
  window_count: number;
  anomaly_count: number;
  started_at: string;
  safe_error?: string | null;
};

type MLStatus = {
  schema_version: number;
  models: MLModel[];
  champions: MLModel[];
  training_runs: MLTrainingRun[];
  scoring_runs: MLScoringRun[];
  legacy_unregistered: boolean;
  legacy_artifact?: { description: string; recommendation: string };
};

type MLModelDetails = {
  model: MLModel & {
    profile_key: string;
    manifest_sha256: string;
    model_artifact_sha256: string;
  };
  evaluation?: {
    label_status: string;
    metrics: Record<string, unknown>;
  } | null;
  verification?: {
    verified?: boolean;
    manifest_sha256?: string;
    model_artifact_sha256?: string;
  };
};

type MLScoringRunDetails = MLScoringRun & {
  windows?: Array<{
    window_id: string;
    window_start: string;
    window_end: string;
    anomaly_score: number;
    risk_level: string;
    is_anomaly: boolean;
  }>;
};

type DriftReport = {
  status: string;
  reference_split?: { count?: number; kind?: string };
  model_score_quantiles?: {
    reference?: Record<string, number>;
    target?: Record<string, number>;
  };
  reference_flagged_rate?: number;
  target_flagged_rate?: number;
  flagged_rate_difference?: number;
  top_shifted_features?: Array<{
    feature_name: string;
    standardized_mean_shift: number;
    psi: number;
  }>;
  limitations?: string[];
};

type DetectionRun = {
  detection_run_id?: string | null;
  child_run_ids?: string[];
  status: string;
  mode: string;
  model_id?: string | null;
  examined_count?: number;
  evaluated_count: number;
  skipped_count: number;
  finding_count: number;
  finding_occurrences?: number;
  new_findings?: number;
  updated_findings?: number;
  no_op_count: number;
  blocked_reason?: string | null;
  safe_error?: string | null;
  started_at?: string;
  completed_at?: string | null;
};

type DetectionStatus = {
  schema_version: number;
  active_policy: {
    policy_id: string;
    policy_version: string;
    policy_hash: string;
    mode: string;
    finding_threshold: number;
    fusion_method: string;
    rules: Array<{ rule_id: string; enabled: boolean }>;
  };
  latest_run?: DetectionRun | null;
  finding_counts: Record<string, number>;
  evaluation_count: number;
  watermarks: Array<{ last_window_start?: string | null; last_window_id?: string | null }>;
  worker?: {
    status?: string;
    heartbeat_at?: string;
    stop_requested?: number;
    worker_key?: string | null;
    lease_expired?: boolean;
    expires_at?: string | null;
  } | null;
};

type DetectionPolicySummary = {
  policy_id: string;
  policy_version: string;
  policy_hash: string;
  mode: string;
  active: boolean;
};

type DetectionFinding = {
  finding_id: string;
  fingerprint: string;
  dataset_kind: string;
  profile_key: string;
  status: string;
  risk_level: Risk | 'none';
  detection_score: number;
  primary_signal_id: string;
  title: string;
  summary: string;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
};

type DetectionFindingDetail = DetectionFinding & {
  occurrences?: Array<{
    occurrence_id: string;
    detection_run_id: string;
    window_id: string;
    window_start: string;
    status: string;
    suppression_id?: string | null;
    suppression_reason?: string | null;
    suppression_expires_at?: string | null;
    matched_signal_ids?: string[];
    decision?: Record<string, unknown>;
    signals?: Array<Record<string, unknown>>;
    evidence?: Array<Record<string, unknown>>;
  }>;
  history?: Array<{
    history_id: string;
    from_status: string;
    to_status: string;
    reason: string;
    created_at: string;
  }>;
};

type DetectionSuppression = {
  suppression_id: string;
  scope: string;
  dataset_kind?: string | null;
  profile_key?: string | null;
  finding_fingerprint?: string | null;
  signal_id?: string | null;
  reason: string;
  expires_at: string;
  revoked_at?: string | null;
};

const copy = {
  en: {
    title: 'SentinelUEBA',
    subtitle: 'Local-first behavior anomaly detection demo',
    generate: 'Generate',
    train: 'Train',
    detect: 'Analyze',
    events: 'Events',
    anomalies: 'Anomalies',
    model: 'Model',
    selected: 'Selected anomaly',
    noSelection: 'Run the demo pipeline and select an anomaly.',
    explanation: 'Explanation',
    collection: 'Windows collection',
    startCollection: 'Start',
    stopCollection: 'Stop',
    cumulative: 'Cumulative',
    continuous: 'Longest session',
    current: 'Current',
    warning: 'Cumulative collection is not the same as strict continuous 24-hour validation.',
    scenarios: 'Demo scenarios',
    dataPipeline: 'Data Pipeline',
    materialize: 'Materialize',
    snapshot: 'Synthetic snapshot',
    retention: 'Retention preview',
    usable: 'Usable real coverage',
    watermark: 'Watermark',
    latestSynthetic: 'Latest synthetic snapshot',
    latestReal: 'Latest real snapshot',
    realDisabled: 'Real snapshot requires 24 usable hours in one profile.',
    mlLab: 'ML Lab',
    trainCandidates: 'Train candidates',
    verifyChampion: 'Verify champion',
    scoreChampion: 'Score champion',
    drift: 'Drift report',
    champion: 'Champion',
    recommended: 'Recommended',
    latestRun: 'Latest training run',
    latestScore: 'Latest scoring run',
    registry: 'SQLite registry',
    modelBundles: 'Model bundles',
    scoringRuns: 'Scoring runs',
    mlWarning: 'Offline model scoring only. An anomaly is not proof of malicious activity.',
    detectionCenter: 'Detection Center',
    runDetection: 'Run detection',
    workerCycle: 'Worker cycle',
    findings: 'Findings',
    activePolicy: 'Active policy',
    fusion: 'Fusion',
    worker: 'Worker',
    evaluations: 'Evaluations',
    findingWarning: 'Findings are triage records, not proof of malicious activity.',
  },
  ru: {
    title: 'SentinelUEBA',
    subtitle: 'Локальное demo обнаружения поведенческих аномалий',
    generate: 'Сгенерировать',
    train: 'Обучить',
    detect: 'Анализ',
    events: 'События',
    anomalies: 'Аномалии',
    model: 'Модель',
    selected: 'Выбранная аномалия',
    noSelection: 'Запустите demo pipeline и выберите аномалию.',
    explanation: 'Объяснение',
    collection: 'Windows сбор',
    startCollection: 'Старт',
    stopCollection: 'Стоп',
    cumulative: 'Накоплено',
    continuous: 'Самый длинный сеанс',
    current: 'Текущий',
    warning: 'Накопительный сбор не равен строгой непрерывной 24-часовой проверке.',
    scenarios: 'Demo-сценарии',
    dataPipeline: 'Data Pipeline',
    materialize: 'Материализовать',
    snapshot: 'Synthetic snapshot',
    retention: 'Retention preview',
    usable: 'Полезное real-покрытие',
    watermark: 'Watermark',
    latestSynthetic: 'Последний synthetic snapshot',
    latestReal: 'Последний real snapshot',
    realDisabled: 'Real snapshot требует 24 полезных часа в одном профиле.',
    mlLab: 'ML Lab',
    trainCandidates: 'Обучить кандидатов',
    verifyChampion: 'Проверить champion',
    scoreChampion: 'Score champion',
    drift: 'Drift report',
    champion: 'Champion',
    recommended: 'Recommended',
    latestRun: 'Последний training run',
    latestScore: 'Последний scoring run',
    registry: 'SQLite registry',
    modelBundles: 'Model bundles',
    scoringRuns: 'Scoring runs',
    mlWarning: 'Только offline scoring. Аномалия не является доказательством атаки.',
    detectionCenter: 'Центр обнаружения',
    runDetection: 'Запустить detection',
    workerCycle: 'Цикл worker',
    findings: 'Findings',
    activePolicy: 'Активная policy',
    fusion: 'Fusion',
    worker: 'Worker',
    evaluations: 'Оценки',
    findingWarning: 'Findings являются triage-записями, а не доказательством атаки.',
  },
};

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const method = (options?.method ?? 'GET').toUpperCase();
  const headers = new Headers(options?.headers);
  headers.set('Content-Type', 'application/json');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const bootstrap = await runtimeBootstrap();
    if (bootstrap?.control_token) {
      headers.set('X-SentinelUEBA-Control-Token', bootstrap.control_token);
    }
  }
  const response = await fetch(`/api${path}`, {
    ...options,
    headers,
  });
  if (!response.ok) throw new Error(await response.text());
  return (await response.json()) as T;
}

export function App() {
  const [locale, setLocale] = React.useState<Locale>('en');
  const [status, setStatus] = React.useState<Status | null>(null);
  const [anomalies, setAnomalies] = React.useState<Anomaly[]>([]);
  const [selected, setSelected] = React.useState<number>(0);
  const [busy, setBusy] = React.useState<string>('');
  const [message, setMessage] = React.useState<string>('Ready');
  const [capabilities, setCapabilities] = React.useState<CollectorCapability[]>([]);
  const [scenarioValidation, setScenarioValidation] = React.useState<ScenarioValidation[]>([]);
  const [dataQuality, setDataQuality] = React.useState<DataQuality | null>(null);
  const [mlStatus, setMlStatus] = React.useState<MLStatus | null>(null);
  const [mlDatasetKind, setMlDatasetKind] = React.useState<'synthetic' | 'real'>('synthetic');
  const [selectedDatasetId, setSelectedDatasetId] = React.useState<string>('');
  const [trainAutoencoder, setTrainAutoencoder] = React.useState<boolean>(true);
  const [trainIsolationForest, setTrainIsolationForest] = React.useState<boolean>(true);
  const [autoencoderEpochs, setAutoencoderEpochs] = React.useState<number>(20);
  const [ifEstimators, setIfEstimators] = React.useState<number>(32);
  const [scoreBatchSize, setScoreBatchSize] = React.useState<number>(64);
  const [modelDetails, setModelDetails] = React.useState<MLModelDetails | null>(null);
  const [scoringRunDetails, setScoringRunDetails] = React.useState<MLScoringRunDetails | null>(
    null,
  );
  const [driftReport, setDriftReport] = React.useState<DriftReport | null>(null);
  const [detectionStatus, setDetectionStatus] = React.useState<DetectionStatus | null>(null);
  const [detectionPolicies, setDetectionPolicies] = React.useState<DetectionPolicySummary[]>([]);
  const [detectionFindings, setDetectionFindings] = React.useState<DetectionFinding[]>([]);
  const [detectionSuppressions, setDetectionSuppressions] = React.useState<
    DetectionSuppression[]
  >([]);
  const [selectedFindingDetail, setSelectedFindingDetail] =
    React.useState<DetectionFindingDetail | null>(null);
  const [detectionDatasetKind, setDetectionDatasetKind] = React.useState<'synthetic' | 'real'>(
    'synthetic',
  );
  const [detectionPolicyHash, setDetectionPolicyHash] = React.useState<string>('');
  const [detectionBackfillStart, setDetectionBackfillStart] = React.useState<string>('');
  const [detectionBackfillEnd, setDetectionBackfillEnd] = React.useState<string>('');
  const [findingStatusFilter, setFindingStatusFilter] = React.useState<string>('all');
  const [findingRiskFilter, setFindingRiskFilter] = React.useState<string>('all');
  const [findingSignalFilter, setFindingSignalFilter] = React.useState<string>('');
  const [findingSinceFilter, setFindingSinceFilter] = React.useState<string>('');
  const [runtime, setRuntime] = React.useState<RuntimeBootstrap | null>(null);
  const t = copy[locale];

  const refresh = React.useCallback(async () => {
    const runtimeResponse = await runtimeBootstrap();
    setRuntime(runtimeResponse);
    const statusResponse = await api<{ data: Status }>('/status');
    const anomalyResponse = await api<{ anomalies: Anomaly[] }>('/anomalies');
    const capabilityResponse = await api<{ data: { collectors: CollectorCapability[] } }>(
      '/collectors/capabilities',
    );
    const qualityResponse = await api<{ data: DataQuality }>('/data-quality');
    const mlStatusResponse = await api<{ data: MLStatus }>('/ml/status');
    const detectionStatusResponse = await api<{ data: DetectionStatus }>('/detection/status');
    const detectionPolicyResponse = await api<{
      data: { policies: DetectionPolicySummary[] };
    }>('/detection/policies');
    const findingQuery = new URLSearchParams({ dataset_kind: detectionDatasetKind });
    if (findingStatusFilter !== 'all') {
      findingQuery.set('status', findingStatusFilter);
    }
    const detectionFindingsResponse = await api<{ data: { findings: DetectionFinding[] } }>(
      `/detection/findings?${findingQuery.toString()}`,
    );
    const suppressionResponse = await api<{ data: { suppressions: DetectionSuppression[] } }>(
      '/detection/suppressions',
    );
    setStatus(statusResponse.data);
    setAnomalies(anomalyResponse.anomalies);
    setCapabilities(capabilityResponse.data.collectors);
    setDataQuality(qualityResponse.data);
    setMlStatus(mlStatusResponse.data);
    setDetectionStatus(detectionStatusResponse.data);
    setDetectionPolicies(detectionPolicyResponse.data.policies);
    if (!detectionPolicyHash) {
      setDetectionPolicyHash(detectionStatusResponse.data.active_policy.policy_hash);
    }
    setDetectionFindings(detectionFindingsResponse.data.findings);
    setDetectionSuppressions(suppressionResponse.data.suppressions);
  }, [detectionDatasetKind, detectionPolicyHash, findingStatusFilter]);

  React.useEffect(() => {
    refresh().catch(() => setMessage('Backend is not reachable'));
  }, [refresh]);

  const run = async (label: string, action: () => Promise<unknown>) => {
    setBusy(label);
    try {
      const result = await action();
      if (isApiData(result) && Array.isArray(result.data.scenario_validation)) {
        setScenarioValidation(result.data.scenario_validation as ScenarioValidation[]);
      }
      setMessage(JSON.stringify(result, null, 2));
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unknown error');
    } finally {
      setBusy('');
    }
  };

  const confirmLifecycle = (action: string, model: MLModel, consequence: string) =>
    window.confirm(
      `${action} ${shortValue(model.model_id)}\n` +
        `Current status: ${model.lifecycle_status}\n` +
        consequence,
    );

  const loadModelDetails = (modelId: string) =>
    run('model-details', async () => {
      const response = await api<{ data: MLModelDetails }>(`/ml/models/${modelId}`);
      setModelDetails(response.data);
      return response;
    });

  const loadScoringRunDetails = (runId: string) =>
    run('scoring-details', async () => {
      const response = await api<{ data: MLScoringRunDetails }>(`/ml/scoring-runs/${runId}`);
      setScoringRunDetails(response.data);
      return response;
    });

  const selectedAnomaly = anomalies[selected];
  const scores = anomalies.slice(0, 24).reverse();
  const maxScore = Math.max(...scores.map((item) => item.anomaly_score), 1);
  const champion = mlStatus?.champions[0];
  const recommended = mlStatus?.models.find((model) => model.lifecycle_status === 'recommended');
  const latestTrainingRun = mlStatus?.training_runs[0];
  const latestScoringRun = mlStatus?.scoring_runs[0];
  const latestDetectionRun = detectionStatus?.latest_run;
  const latestWatermark = detectionStatus?.watermarks[0];
  const selectedDetectionPolicy =
    detectionPolicies.find((policy) => policy.policy_hash === detectionPolicyHash) ??
    detectionPolicies.find((policy) => policy.active) ??
    detectionPolicies[0];
  const filteredDetectionFindings = detectionFindings.filter((finding) => {
    if (findingRiskFilter !== 'all' && finding.risk_level !== findingRiskFilter) {
      return false;
    }
    if (
      findingSignalFilter &&
      !finding.primary_signal_id.toLowerCase().includes(findingSignalFilter.toLowerCase())
    ) {
      return false;
    }
    if (findingSinceFilter && new Date(finding.last_seen_at) < new Date(findingSinceFilter)) {
      return false;
    }
    return true;
  });
  const availableDatasets = dataQuality?.dataset_snapshots[mlDatasetKind] ?? [];
  const effectiveDatasetId = selectedDatasetId || availableDatasets[0]?.dataset_id || '';
  const selectedFamilies = [
    trainAutoencoder ? 'autoencoder' : '',
    trainIsolationForest ? 'isolation-forest' : '',
  ].filter(Boolean);
  const stage3ModelStatus = champion
    ? `champion ${shortValue(champion.model_id)}`
    : mlStatus?.legacy_unregistered
      ? 'legacy'
      : status?.model.trained
        ? 'legacy'
        : 'missing';

  return (
    <main>
      <header className="topbar">
        <div>
          <h1>{t.title}</h1>
          <p>
            {t.subtitle}
            {runtime ? ` · v${runtime.version} · ${runtime.mode}` : ''}
          </p>
        </div>
        <div className="topActions">
          {runtime?.mode === 'desktop' && (
            <button
              className="iconButton"
              onClick={() => {
                if (window.confirm('Exit local application?')) {
                  run('shutdown', () =>
                    api('/runtime/shutdown', {
                      method: 'POST',
                      body: JSON.stringify({ confirm: true }),
                    }),
                  );
                }
              }}
              title="Exit local application"
            >
              <Square size={18} />
              Exit
            </button>
          )}
          <button
            className="iconButton"
            onClick={() => setLocale(locale === 'en' ? 'ru' : 'en')}
            title="Language"
          >
            <Languages size={18} />
            {locale.toUpperCase()}
          </button>
        </div>
      </header>

      <section className="toolbar">
        <button onClick={() => run('generate', () => api('/demo/generate', { method: 'POST', body: JSON.stringify({ seed: 42 }) }))}>
          <Database size={17} /> {t.generate}
        </button>
        <button onClick={() => run('train', () => api('/model/train', { method: 'POST', body: JSON.stringify({ seed: 42 }) }))}>
          <Sparkles size={17} /> {t.train}
        </button>
        <button onClick={() => run('detect', () => api('/detect', { method: 'POST' }))}>
          <Play size={17} /> {t.detect}
        </button>
        <span className="busy">{busy || 'idle'}</span>
      </section>

      <section className="collectionPanel">
        <div className="panelTitle">
          <Shield size={18} />
          <span>{t.collection}</span>
        </div>
        <div className="collectionActions">
          <button onClick={() => run('collect', () => api('/collection/start', { method: 'POST', body: JSON.stringify({ interval_seconds: 5 }) }))}>
            <Play size={17} /> {t.startCollection}
          </button>
          <button onClick={() => run('stop', () => api('/collection/stop', { method: 'POST' }))}>
            <Square size={17} /> {t.stopCollection}
          </button>
          <strong>{status?.collection?.running ? 'running' : 'stopped'}</strong>
        </div>
        <div className="progressLine">
          <span>{t.cumulative}: {formatDuration(status?.collection?.progress.cumulative_collected_seconds ?? 0)}</span>
          <span>{t.continuous}: {formatDuration(status?.collection?.progress.longest_continuous_session_seconds ?? 0)}</span>
          <span>{t.current}: {formatDuration(status?.collection?.progress.current_session_seconds ?? 0)}</span>
          <span>{Math.round((status?.collection?.progress.progress_to_24h ?? 0) * 100)}%</span>
        </div>
        <p className="warning">{t.warning}</p>
        <div className="collectorGrid">
          {capabilities.map((collector) => (
            <article key={collector.collector_id}>
              <strong>{collector.collector_id}</strong>
              <span>{collector.status}</span>
              <span>{collector.required_privilege}</span>
              <small>{collector.errors.join(', ')}</small>
            </article>
          ))}
        </div>
        <div className="eventCounts">
          {['process', 'network', 'system_metrics', 'authentication'].map((eventType) => (
            <span key={eventType}>{eventType}: {status?.collection?.event_summary?.real?.[eventType] ?? 0}</span>
          ))}
        </div>
        {status?.collection?.errors?.length ? <p className="warning">{status.collection.errors.slice(-3).join(' | ')}</p> : null}
      </section>

      <section className="metrics">
        <article>
          <Database size={18} />
          <span>{t.events}</span>
          <strong>{status?.storage.event_count ?? 0}</strong>
        </article>
        <article>
          <Radar size={18} />
          <span>{t.anomalies}</span>
          <strong>{status?.storage.anomaly_count ?? anomalies.length}</strong>
        </article>
        <article>
          <Shield size={18} />
          <span>{t.model}</span>
          <strong>{stage3ModelStatus}</strong>
        </article>
      </section>

      <section className="pipelinePanel">
        <div className="panelTitle">
          <Archive size={18} />
          <span>{t.dataPipeline}</span>
        </div>
        <div className="pipelineActions">
          <button onClick={() => run('materialize', () => api('/features/materialize', { method: 'POST', body: JSON.stringify({ dataset_kind: 'synthetic' }) }))}>
            <RefreshCw size={17} /> {t.materialize}
          </button>
          <button onClick={() => run('snapshot', () => api('/datasets', { method: 'POST', body: JSON.stringify({ dataset_kind: 'synthetic' }) }))}>
            <Database size={17} /> {t.snapshot}
          </button>
          <button disabled title={t.realDisabled}>
            <Database size={17} /> Real snapshot
          </button>
          <button onClick={() => run('retention', () => api('/retention/preview'))}>
            <Shield size={17} /> {t.retention}
          </button>
        </div>
        <div className="pipelineGrid">
          <article>
            <span>{t.events}</span>
            <strong>{status?.storage.event_count ?? 0}</strong>
          </article>
          <article>
            <span>Quarantine</span>
            <strong>{dataQuality?.quarantine.count ?? status?.storage.quarantine_count ?? 0}</strong>
          </article>
          <article>
            <span>Good / degraded / insufficient</span>
            <strong>{qualityText(dataQuality?.window_quality)}</strong>
          </article>
          <article>
            <span>{t.usable}</span>
            <strong>{formatDuration(dataQuality?.usable_coverage_seconds ?? 0)}</strong>
          </article>
          <article>
            <span>24h progress</span>
            <strong>{Math.round((dataQuality?.collection_progress.progress_to_24h ?? 0) * 100)}%</strong>
          </article>
          <article>
            <span>{t.watermark}</span>
            <strong>{shortValue(dataQuality?.watermark.synthetic)}</strong>
          </article>
          <article>
            <span>{t.latestSynthetic}</span>
            <strong>{shortValue(dataQuality?.dataset_snapshots.synthetic[0]?.dataset_id)}</strong>
          </article>
          <article>
            <span>{t.latestReal}</span>
            <strong>{shortValue(dataQuality?.dataset_snapshots.real[0]?.dataset_id)}</strong>
          </article>
        </div>
      </section>

      <section className="mlPanel">
        <div className="panelTitle">
          <Sparkles size={18} />
          <span>{t.mlLab}</span>
        </div>
        <div className="mlControls">
          <label>
            Dataset kind
            <select
              value={mlDatasetKind}
              onChange={(event) => {
                setMlDatasetKind(event.target.value as 'synthetic' | 'real');
                setSelectedDatasetId('');
              }}
            >
              <option value="synthetic">synthetic</option>
              <option value="real">real</option>
            </select>
          </label>
          <label>
            Dataset
            <select
              value={effectiveDatasetId}
              onChange={(event) => setSelectedDatasetId(event.target.value)}
            >
              {availableDatasets.length ? (
                availableDatasets.map((dataset) => (
                  <option key={dataset.dataset_id} value={dataset.dataset_id}>
                    {shortValue(dataset.dataset_id)} / {shortValue(dataset.manifest_sha256)}
                  </option>
                ))
              ) : (
                <option value="">none</option>
              )}
            </select>
          </label>
          <label className="checkControl">
            <input
              type="checkbox"
              checked={trainAutoencoder}
              onChange={(event) => setTrainAutoencoder(event.target.checked)}
            />
            Autoencoder
          </label>
          <label className="checkControl">
            <input
              type="checkbox"
              checked={trainIsolationForest}
              onChange={(event) => setTrainIsolationForest(event.target.checked)}
            />
            Isolation Forest
          </label>
          <label>
            AE epochs
            <input
              type="number"
              min={1}
              max={300}
              value={autoencoderEpochs}
              onChange={(event) => setAutoencoderEpochs(Number(event.target.value))}
            />
          </label>
          <label>
            IF estimators
            <input
              type="number"
              min={10}
              max={500}
              value={ifEstimators}
              onChange={(event) => setIfEstimators(Number(event.target.value))}
            />
          </label>
          <label>
            Batch
            <input
              type="number"
              min={1}
              max={4096}
              value={scoreBatchSize}
              onChange={(event) => setScoreBatchSize(Number(event.target.value))}
            />
          </label>
        </div>
        <div className="pipelineActions">
          <button
            disabled={!selectedFamilies.length}
            onClick={() =>
              run(
                'ml-train',
                () =>
                  api('/ml/train', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: mlDatasetKind,
                      dataset_id: effectiveDatasetId || undefined,
                      families: selectedFamilies,
                      seed: 42,
                      autoencoder: {
                        epochs: autoencoderEpochs,
                        batch_size: 16,
                        learning_rate: 0.005,
                        weight_decay: 0.0001,
                        hidden_dim: 10,
                        latent_dim: 4,
                        plateau_patience: 12,
                      },
                      isolation_forest: {
                        n_estimators: ifEstimators,
                        max_samples: 'auto',
                        max_features: 1,
                        bootstrap: false,
                        n_jobs: 1,
                      },
                    }),
                  }),
              )
            }
          >
            <Sparkles size={17} /> {t.trainCandidates}
          </button>
          <button
            disabled={!champion}
            onClick={() =>
              champion
                ? run(
                    'ml-verify',
                    () => api(`/ml/models/${champion.model_id}/verify`, { method: 'POST' }),
                  )
                : undefined
            }
          >
            <Shield size={17} /> {t.verifyChampion}
          </button>
          <button
            disabled={!champion}
            onClick={() =>
              champion
                ? run(
                    'ml-score',
                    () =>
                      api('/ml/score', {
                        method: 'POST',
                        body: JSON.stringify({
                          dataset_id: champion.dataset_id,
                          model_id: champion.model_id,
                          batch_size: scoreBatchSize,
                        }),
                      }),
                  )
                : undefined
            }
          >
            <Play size={17} /> {t.scoreChampion}
          </button>
          <button
            disabled={!champion}
            onClick={() =>
              champion
                ? run(
                    'ml-drift',
                    async () => {
                      const response = await api<{ data: DriftReport }>('/ml/drift', {
                        method: 'POST',
                        body: JSON.stringify({
                          dataset_id: champion.dataset_id,
                          model_id: champion.model_id,
                        }),
                      });
                      setDriftReport(response.data);
                      return response;
                    },
                  )
                : undefined
            }
          >
            <Activity size={17} /> {t.drift}
          </button>
        </div>
        <div className="mlGrid">
          <article>
            <span>{t.registry}</span>
            <strong>v{mlStatus?.schema_version ?? 0}</strong>
          </article>
          <article>
            <span>{t.modelBundles}</span>
            <strong>{status?.storage.model_count ?? mlStatus?.models.length ?? 0}</strong>
          </article>
          <article>
            <span>{t.scoringRuns}</span>
            <strong>{status?.storage.scoring_run_count ?? mlStatus?.scoring_runs.length ?? 0}</strong>
          </article>
          <article>
            <span>{t.champion}</span>
            <strong>{shortValue(champion?.model_id)}</strong>
          </article>
          <article>
            <span>{t.recommended}</span>
            <strong>{shortValue(recommended?.model_id)}</strong>
          </article>
          <article>
            <span>{t.latestRun}</span>
            <strong>
              {latestTrainingRun
                ? `${latestTrainingRun.status} ${shortValue(latestTrainingRun.training_run_id)}`
                : 'none'}
            </strong>
          </article>
          <article>
            <span>{t.latestScore}</span>
            <strong>{latestScoringRun ? `${latestScoringRun.anomaly_count}/${latestScoringRun.window_count}` : 'none'}</strong>
          </article>
          <article>
            <span>Threshold</span>
            <strong>{champion ? champion.threshold.toFixed(4) : 'none'}</strong>
          </article>
          <article>
            <span>Legacy</span>
            <strong>{mlStatus?.legacy_unregistered ? 'unregistered' : 'none'}</strong>
          </article>
        </div>
        <p className="warning">{t.mlWarning}</p>
        {mlStatus?.legacy_unregistered ? (
          <p className="warning">{mlStatus.legacy_artifact?.recommendation}</p>
        ) : null}
        <div className="mlTables">
          <div>
            <h3>Models</h3>
            <div className="table compactTable">
              {(mlStatus?.models ?? []).map((model) => (
                <div className="row" key={model.model_id}>
                  <span>{shortValue(model.model_id)}</span>
                  <span>{model.family}</span>
                  <span>{model.lifecycle_status}</span>
                  <span>{model.dataset_kind}</span>
                  <span>{model.threshold.toFixed(4)}</span>
                  <span>{model.verified_at ? 'verified' : 'pending'}</span>
                  <button onClick={() => loadModelDetails(model.model_id)}>details</button>
                  <button
                    disabled={model.lifecycle_status !== 'candidate'}
                    onClick={() => {
                      if (
                        confirmLifecycle(
                          'Recommend',
                          model,
                          'The model becomes the preferred candidate, but not champion.',
                        )
                      ) {
                        run('recommend', () =>
                          api(`/ml/models/${model.model_id}/recommend`, {
                            method: 'POST',
                            body: JSON.stringify({
                              confirm: true,
                              reason: 'ML Lab recommendation',
                            }),
                          }),
                        );
                      }
                    }}
                  >
                    {t.recommended}
                  </button>
                  <button
                    disabled={!['candidate', 'recommended'].includes(model.lifecycle_status)}
                    onClick={() => {
                      if (
                        confirmLifecycle(
                          'Promote',
                          model,
                          'The current champion for this profile will be retired.',
                        )
                      ) {
                        run('promote', () =>
                          api(`/ml/models/${model.model_id}/promote`, {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true, reason: 'ML Lab promotion' }),
                          }),
                        );
                      }
                    }}
                  >
                    {t.champion}
                  </button>
                  <button
                    disabled={model.lifecycle_status !== 'champion'}
                    onClick={() => {
                      if (
                        confirmLifecycle(
                          'Retire',
                          model,
                          'The profile will have no champion until another model is promoted.',
                        )
                      ) {
                        run('retire', () =>
                          api(`/ml/models/${model.model_id}/retire`, {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true, reason: 'ML Lab retirement' }),
                          }),
                        );
                      }
                    }}
                  >
                    retire
                  </button>
                  <button
                    disabled={model.lifecycle_status !== 'retired'}
                    onClick={() => {
                      if (
                        confirmLifecycle(
                          'Rollback',
                          model,
                          'This retired model becomes champion and the current champion retires.',
                        )
                      ) {
                        run('rollback', () =>
                          api(`/ml/models/${model.model_id}/rollback`, {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true, reason: 'ML Lab rollback' }),
                          }),
                        );
                      }
                    }}
                  >
                    rollback
                  </button>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3>Training runs</h3>
            <div className="table compactTable">
              {(mlStatus?.training_runs ?? []).map((run) => (
                <div className="row" key={run.training_run_id}>
                  <span>{shortValue(run.training_run_id)}</span>
                  <span>{run.dataset_kind}</span>
                  <span>{shortValue(run.profile_key)}</span>
                  <span>{run.status}</span>
                  <span>{shortValue(run.split_id)}</span>
                  <span>{run.safe_error_message ? 'failed safely' : 'ok'}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3>Scoring runs</h3>
            <div className="table compactTable">
              {(mlStatus?.scoring_runs ?? []).map((run) => (
                <div className="row" key={run.scoring_run_id}>
                  <span>{shortValue(run.scoring_run_id)}</span>
                  <span>{shortValue(run.model_id)}</span>
                  <span>{run.split_range?.kind ?? 'snapshot'}</span>
                  <span>{run.status}</span>
                  <span>{run.anomaly_count}/{run.window_count}</span>
                  <span>{run.safe_error ? 'failed safely' : 'ok'}</span>
                  <button onClick={() => loadScoringRunDetails(run.scoring_run_id)}>
                    details
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="detailGrid">
          <article>
            <h3>Model details</h3>
            {modelDetails ? (
              <div className="detailList">
                <span>Profile {shortValue(modelDetails.model.profile_key)}</span>
                <span>{modelDetails.model.family} / {modelDetails.model.model_version}</span>
                <span>Lifecycle {modelDetails.model.lifecycle_status}</span>
                <span>Verification {modelDetails.verification?.verified ? 'verified' : 'failed'}</span>
                <span>Manifest {shortValue(modelDetails.model.manifest_sha256)}</span>
                <span>Artifact {shortValue(modelDetails.model.model_artifact_sha256)}</span>
                <span>Label {modelDetails.evaluation?.label_status ?? 'unknown'}</span>
                <span>Split {metricText(modelDetails.evaluation?.metrics, 'train_count')} / {metricText(modelDetails.evaluation?.metrics, 'calibration_count')} / {metricText(modelDetails.evaluation?.metrics, 'test_count')}</span>
                <span>Threshold {metricText(modelDetails.evaluation?.metrics, 'threshold')}</span>
                <span>Calibration flagged {metricText(modelDetails.evaluation?.metrics, 'calibration_flagged_rate')}</span>
                <span>Scenario recall {metricText(modelDetails.evaluation?.metrics, 'scenario_recall')}</span>
                <span>FPR {metricText(modelDetails.evaluation?.metrics, 'false_positive_rate')}</span>
                <span>Precision {metricText(modelDetails.evaluation?.metrics, 'precision')}</span>
                <span>Recall {metricText(modelDetails.evaluation?.metrics, 'recall')}</span>
                <span>F1 {metricText(modelDetails.evaluation?.metrics, 'f1')}</span>
                <span>PR-AUC {metricText(modelDetails.evaluation?.metrics, 'pr_auc')}</span>
                <span>{limitationsText(modelDetails.evaluation?.metrics)}</span>
              </div>
            ) : (
              <p>Select a model.</p>
            )}
          </article>
          <article>
            <h3>Scoring details</h3>
            {scoringRunDetails ? (
              <div className="detailList">
                <span>{scoringRunDetails.status}</span>
                <span>Model {shortValue(scoringRunDetails.model_id)}</span>
                <span>Dataset {shortValue(scoringRunDetails.dataset_id)}</span>
                <span>Range {scoringRunDetails.split_range?.kind ?? 'snapshot'}</span>
                <span>{scoringRunDetails.anomaly_count}/{scoringRunDetails.window_count}</span>
                <span>{scoringRunDetails.safe_error ?? 'no safe error'}</span>
                {(scoringRunDetails.windows ?? []).slice(0, 5).map((window) => (
                  <span key={window.window_id}>
                    {shortValue(window.window_id)} {window.risk_level} {window.anomaly_score.toFixed(4)}
                  </span>
                ))}
              </div>
            ) : (
              <p>Select a scoring run.</p>
            )}
          </article>
          <article>
            <h3>Drift report</h3>
            {driftReport ? (
              <div className="detailList">
                <span>Status {driftReport.status}</span>
                <span>Reference {driftReport.reference_split?.count ?? 0}</span>
                <span>Reference flagged {formatMaybe(driftReport.reference_flagged_rate)}</span>
                <span>Target flagged {formatMaybe(driftReport.target_flagged_rate)}</span>
                <span>Difference {formatMaybe(driftReport.flagged_rate_difference)}</span>
                <span>Reference scores {quantileText(driftReport.model_score_quantiles?.reference)}</span>
                <span>Target scores {quantileText(driftReport.model_score_quantiles?.target)}</span>
                {(driftReport.top_shifted_features ?? []).slice(0, 5).map((feature) => (
                  <span key={feature.feature_name}>
                    {feature.feature_name}: shift {feature.standardized_mean_shift.toFixed(3)}, PSI {feature.psi.toFixed(3)}
                  </span>
                ))}
                <span>{(driftReport.limitations ?? []).join('; ')}</span>
              </div>
            ) : (
              <p>Run drift.</p>
            )}
          </article>
        </div>
      </section>

      <section className="detectionPanel">
        <div className="panelTitle">
          <Bell size={18} />
          <span>{t.detectionCenter}</span>
        </div>
        <div className="detectionControls">
          <label>
            Dataset
            <select
              value={detectionDatasetKind}
              onChange={(event) =>
                setDetectionDatasetKind(event.target.value as 'synthetic' | 'real')
              }
            >
              <option value="synthetic">synthetic</option>
              <option value="real">real</option>
            </select>
          </label>
          <label>
            Policy
            <select
              value={detectionPolicyHash}
              onChange={(event) => setDetectionPolicyHash(event.target.value)}
            >
              {detectionPolicies.map((policy) => (
                <option key={policy.policy_hash} value={policy.policy_hash}>
                  {policy.policy_id} / {policy.mode}
                  {policy.active ? ' / active' : ''}
                </option>
              ))}
            </select>
          </label>
          <label>
            Backfill start
            <input
              value={detectionBackfillStart}
              onChange={(event) => setDetectionBackfillStart(event.target.value)}
              placeholder="2026-07-27T00:00:00Z"
            />
          </label>
          <label>
            Backfill end
            <input
              value={detectionBackfillEnd}
              onChange={(event) => setDetectionBackfillEnd(event.target.value)}
              placeholder="2026-07-27T23:59:59Z"
            />
          </label>
        </div>
        <div className="pipelineActions">
          <button
            onClick={() =>
              run(
                'detection',
                () =>
                  api('/detection/run-once', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: detectionDatasetKind,
                      policy_id: selectedDetectionPolicy?.policy_id,
                      policy_version: selectedDetectionPolicy?.policy_version,
                    }),
                  }),
              )
            }
          >
            <Play size={17} /> {t.runDetection}
          </button>
          <button
            onClick={() =>
              run(
                'detection-dry-run',
                () =>
                  api('/detection/run-once', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: detectionDatasetKind,
                      policy_id: selectedDetectionPolicy?.policy_id,
                      policy_version: selectedDetectionPolicy?.policy_version,
                      dry_run: true,
                    }),
                  }),
              )
            }
          >
            <Radar size={17} /> dry-run
          </button>
          <button
            disabled={!selectedDetectionPolicy}
            onClick={() => {
              if (window.confirm(`Activate ${selectedDetectionPolicy?.policy_id}?`)) {
                run(
                  'policy-activate',
                  () =>
                    api(`/detection/policies/${selectedDetectionPolicy?.policy_id}/activate`, {
                      method: 'POST',
                      body: JSON.stringify({
                        policy_version: selectedDetectionPolicy?.policy_version,
                        confirm: true,
                        reason: 'Detection Center activation',
                      }),
                    }),
                );
              }
            }}
          >
            <Shield size={17} /> activate
          </button>
          <button
            disabled={!selectedDetectionPolicy || !detectionBackfillStart || !detectionBackfillEnd}
            onClick={() => {
              if (window.confirm('Run confirmed detection backfill?')) {
                run(
                  'detection-backfill',
                  () =>
                    api('/detection/backfill', {
                      method: 'POST',
                      body: JSON.stringify({
                        dataset_kind: detectionDatasetKind,
                        policy_id: selectedDetectionPolicy?.policy_id,
                        policy_version: selectedDetectionPolicy?.policy_version,
                        start: detectionBackfillStart,
                        end: detectionBackfillEnd,
                        confirm: true,
                      }),
                    }),
                );
              }
            }}
          >
            <Archive size={17} /> backfill
          </button>
          <button
            onClick={() =>
              run(
                'worker-start',
                () =>
                  api('/detection/worker/start', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: detectionDatasetKind,
                      interval_seconds: 60,
                      max_windows: 256,
                    }),
                  }),
              )
            }
          >
            <Play size={17} /> worker start
          </button>
          <button
            onClick={() =>
              run(
                'worker-stop',
                () =>
                  api('/detection/worker/stop', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: detectionDatasetKind,
                      confirm: true,
                    }),
                  }),
              )
            }
          >
            <Square size={17} /> worker stop
          </button>
          <button
            onClick={() =>
              run(
                'detection-worker',
                () =>
                  api('/detection/worker/run-foreground', {
                    method: 'POST',
                    body: JSON.stringify({
                      dataset_kind: detectionDatasetKind,
                      max_windows: 256,
                      single_cycle: true,
                    }),
                  }),
              )
            }
          >
            <RefreshCw size={17} /> {t.workerCycle}
          </button>
          <button onClick={() => refresh()}>
            <RefreshCw size={17} /> refresh
          </button>
        </div>
        <div className="detectionGrid">
          <article>
            <span>{t.activePolicy}</span>
            <strong>{detectionStatus?.active_policy.policy_id ?? 'none'}</strong>
          </article>
          <article>
            <span>Schema</span>
            <strong>v{detectionStatus?.schema_version ?? 'n/a'}</strong>
          </article>
          <article>
            <span>{t.fusion}</span>
            <strong>{detectionStatus?.active_policy.fusion_method ?? 'none'}</strong>
          </article>
          <article>
            <span>Policy hash</span>
            <strong>{shortValue(detectionStatus?.active_policy.policy_hash)}</strong>
          </article>
          <article>
            <span>Mode / threshold</span>
            <strong>
              {detectionStatus
                ? `${detectionStatus.active_policy.mode} / ${detectionStatus.active_policy.finding_threshold}`
                : 'none'}
            </strong>
          </article>
          <article>
            <span>{t.worker}</span>
            <strong>
              {detectionStatus?.worker?.status ?? 'stopped'}
              {detectionStatus?.worker?.lease_expired ? ' / expired' : ''}
            </strong>
          </article>
          <article>
            <span>Worker key</span>
            <strong>{shortValue(detectionStatus?.worker?.worker_key)}</strong>
          </article>
          <article>
            <span>{t.evaluations}</span>
            <strong>{detectionStatus?.evaluation_count ?? 0}</strong>
          </article>
          <article>
            <span>{t.findings}</span>
            <strong>{Object.values(detectionStatus?.finding_counts ?? {}).reduce((a, b) => a + b, 0)}</strong>
          </article>
          <article>
            <span>Latest run</span>
            <strong>
              {latestDetectionRun
                ? `${latestDetectionRun.status} ${latestDetectionRun.finding_count}/${latestDetectionRun.evaluated_count}`
                : 'none'}
            </strong>
          </article>
          <article>
            <span>Run audit</span>
            <strong>
              {latestDetectionRun
                ? `${latestDetectionRun.examined_count ?? 0} examined / ${latestDetectionRun.skipped_count} skipped`
                : 'none'}
            </strong>
          </article>
          <article>
            <span>Occurrences</span>
            <strong>
              {latestDetectionRun
                ? `${latestDetectionRun.finding_occurrences ?? 0} occ / ${latestDetectionRun.new_findings ?? 0} new`
                : 'none'}
            </strong>
          </article>
          <article>
            <span>{t.watermark}</span>
            <strong>{shortValue(latestWatermark?.last_window_start)}</strong>
          </article>
          <article>
            <span>Watermark id</span>
            <strong>{shortValue(latestWatermark?.last_window_id)}</strong>
          </article>
        </div>
        <p className="warning">{t.findingWarning}</p>
        <div className="detectionFilters">
          <label>
            Status
            <select
              value={findingStatusFilter}
              onChange={(event) => setFindingStatusFilter(event.target.value)}
            >
              <option value="all">all</option>
              <option value="open">open</option>
              <option value="acknowledged">acknowledged</option>
              <option value="investigating">investigating</option>
              <option value="suppressed">suppressed</option>
              <option value="resolved">resolved</option>
              <option value="false_positive">false positive</option>
            </select>
          </label>
          <label>
            Risk
            <select
              value={findingRiskFilter}
              onChange={(event) => setFindingRiskFilter(event.target.value)}
            >
              <option value="all">all</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
              <option value="none">none</option>
            </select>
          </label>
          <label>
            Signal
            <input
              value={findingSignalFilter}
              onChange={(event) => setFindingSignalFilter(event.target.value)}
              placeholder="rare-process-v1"
            />
          </label>
          <label>
            Since
            <input
              value={findingSinceFilter}
              onChange={(event) => setFindingSinceFilter(event.target.value)}
              placeholder="2026-07-27T00:00:00Z"
            />
          </label>
        </div>
        <div className="table findingTable">
          {filteredDetectionFindings.slice(0, 12).map((finding) => (
            <div className="row" key={finding.finding_id}>
              <span>{shortValue(finding.finding_id)}</span>
              <span className={`risk ${finding.risk_level}`}>{finding.risk_level}</span>
              <span>{finding.status}</span>
              <span>{finding.detection_score}</span>
              <span>{finding.primary_signal_id}</span>
              <span>{finding.occurrence_count}</span>
              <button
                onClick={() =>
                  run('finding-detail', async () => {
                    const response = await api<{ data: DetectionFindingDetail }>(
                      `/detection/findings/${finding.finding_id}`,
                    );
                    setSelectedFindingDetail(response.data);
                    return response;
                  })
                }
              >
                detail
              </button>
              <button
                disabled={finding.status !== 'open'}
                onClick={() =>
                  run(
                    'ack',
                    () =>
                      api(`/detection/findings/${finding.finding_id}/acknowledge`, {
                        method: 'POST',
                        body: JSON.stringify({ reason: 'Detection Center acknowledge' }),
                      }),
                  )
                }
              >
                ack
              </button>
              <button
                disabled={!['open', 'acknowledged'].includes(finding.status)}
                onClick={() =>
                  run(
                    'investigate',
                    () =>
                      api(`/detection/findings/${finding.finding_id}/investigate`, {
                        method: 'POST',
                        body: JSON.stringify({ reason: 'Detection Center investigation' }),
                      }),
                  )
                }
              >
                investigate
              </button>
              <button
                disabled={!['open', 'acknowledged', 'investigating'].includes(finding.status)}
                onClick={() => {
                  if (window.confirm(`Resolve ${shortValue(finding.finding_id)}?`)) {
                    run(
                      'resolve',
                      () =>
                        api(`/detection/findings/${finding.finding_id}/resolve`, {
                          method: 'POST',
                          body: JSON.stringify({
                            reason: 'Detection Center resolution',
                            confirm: true,
                          }),
                        }),
                    );
                  }
                }}
              >
                resolve
              </button>
              <button
                disabled={!['open', 'acknowledged', 'investigating'].includes(finding.status)}
                onClick={() => {
                  if (window.confirm(`False positive ${shortValue(finding.finding_id)}?`)) {
                    run(
                      'false-positive',
                      () =>
                        api(`/detection/findings/${finding.finding_id}/false-positive`, {
                          method: 'POST',
                          body: JSON.stringify({
                            reason: 'Detection Center false positive',
                            confirm: true,
                          }),
                        }),
                    );
                  }
                }}
              >
                false+
              </button>
              <button
                onClick={() => {
                  if (window.confirm(`Suppress ${shortValue(finding.finding_id)} for 60 min?`)) {
                    run(
                      'suppress',
                      () =>
                        api('/detection/suppressions', {
                          method: 'POST',
                          body: JSON.stringify({
                            scope: 'finding_fingerprint',
                            finding_fingerprint: finding.fingerprint,
                            ttl_minutes: 60,
                            reason: 'Detection Center suppression',
                          }),
                        }),
                    );
                  }
                }}
              >
                suppress
              </button>
            </div>
          ))}
        </div>
        <div className="detailGrid">
          <article>
            <span>Finding detail</span>
            {selectedFindingDetail ? (
              <div className="detailList">
                <strong>{selectedFindingDetail.title}</strong>
                <span>{selectedFindingDetail.summary}</span>
                <span>Status {selectedFindingDetail.status}</span>
                <span>Profile {shortValue(selectedFindingDetail.profile_key)}</span>
                <span>Primary signal {selectedFindingDetail.primary_signal_id}</span>
                <span>Occurrences {selectedFindingDetail.occurrences?.length ?? 0}</span>
                <span>History {selectedFindingDetail.history?.length ?? 0}</span>
              </div>
            ) : (
              <p>Select a finding.</p>
            )}
          </article>
          <article>
            <span>Occurrences / evidence</span>
            <div className="detailList">
              {(selectedFindingDetail?.occurrences ?? []).slice(0, 3).map((occurrence) => (
                <span key={occurrence.occurrence_id}>
                  {shortValue(occurrence.window_id)} {occurrence.status} signals{' '}
                  {(occurrence.matched_signal_ids ?? []).join(', ') || 'none'} evidence{' '}
                  {(occurrence.evidence ?? []).length}
                </span>
              ))}
              {selectedFindingDetail?.occurrences?.[0]?.decision ? (
                <span>
                  Fusion{' '}
                  {JSON.stringify(selectedFindingDetail.occurrences[0].decision).slice(0, 180)}
                </span>
              ) : (
                <span>Fusion none</span>
              )}
            </div>
          </article>
          <article>
            <span>Lifecycle history</span>
            <div className="detailList">
              {(selectedFindingDetail?.history ?? []).slice(-5).map((item) => (
                <span key={item.history_id}>
                  {item.from_status} to {item.to_status}: {item.reason}
                </span>
              ))}
            </div>
          </article>
          <article>
            <span>Active suppressions</span>
            <div className="detailList">
              {detectionSuppressions
                .filter((item) => !item.revoked_at)
                .slice(0, 5)
                .map((item) => (
                  <span key={item.suppression_id}>
                    {item.scope} {item.signal_id ?? shortValue(item.finding_fingerprint)} until{' '}
                    {shortValue(item.expires_at)}
                    <button
                      onClick={() => {
                        if (window.confirm(`Revoke ${shortValue(item.suppression_id)}?`)) {
                          run(
                            'revoke-suppression',
                            () =>
                              api(`/detection/suppressions/${item.suppression_id}/revoke`, {
                                method: 'POST',
                                body: JSON.stringify({ confirm: true }),
                              }),
                          );
                        }
                      }}
                    >
                      revoke
                    </button>
                  </span>
                ))}
            </div>
          </article>
        </div>
      </section>

      <section className="grid">
        <div className="panel chartPanel">
          <div className="panelTitle">
            <Activity size={18} />
            <span>Anomaly score</span>
          </div>
          <div className="chart">
            {scores.map((item, index) => (
              <button
                key={`${item.timestamp}-${index}`}
                className={`bar ${item.risk_level}`}
                style={{ height: `${Math.max(8, (item.anomaly_score / maxScore) * 100)}%` }}
                title={`${item.risk_level}: ${item.anomaly_score.toFixed(4)}`}
                onClick={() => setSelected(anomalies.indexOf(item))}
              />
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panelTitle">
            <Radar size={18} />
            <span>{t.anomalies}</span>
          </div>
          <div className="table">
            {anomalies.slice(0, 12).map((item, index) => (
              <button key={`${item.timestamp}-${index}`} className="row" onClick={() => setSelected(index)}>
                <span>{new Date(item.timestamp).toLocaleString()}</span>
                <span className={`risk ${item.risk_level}`}>{item.risk_level}</span>
                <span>{item.anomaly_score.toFixed(4)}</span>
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="details">
        <h2>{t.selected}</h2>
        {selectedAnomaly ? (
          <>
            <p className={`riskText ${selectedAnomaly.risk_level}`}>{selectedAnomaly.risk_level}</p>
            <p>{selectedAnomaly.timestamp}</p>
            <p>{selectedAnomaly.top_features.join(', ')}</p>
            <h3>{t.explanation}</h3>
            <p>{selectedAnomaly.explanation}</p>
          </>
        ) : (
          <p>{t.noSelection}</p>
        )}
      </section>

      {scenarioValidation.length ? (
        <section className="details">
          <h2>{t.scenarios}</h2>
          <div className="scenarioGrid">
            {scenarioValidation.map((scenario) => (
              <article key={scenario.scenario_name}>
                <strong>{scenario.scenario_name}</strong>
                <span>{scenario.detected ? 'detected' : 'missed'}</span>
                <span>{scenario.max_risk_level ?? 'offline'}</span>
                <span>{scenario.best_anomaly_score.toFixed(4)}</span>
              </article>
            ))}
          </div>
        </section>
      ) : null}


      <pre className="log">{message}</pre>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

function formatDuration(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(safeSeconds / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

function isApiData(value: unknown): value is { data: { scenario_validation?: unknown } } {
  return typeof value === 'object' && value !== null && 'data' in value;
}

function qualityText(quality?: Record<string, Record<string, number>>): string {
  if (!quality) return '0 / 0 / 0';
  const totals = Object.values(quality).reduce(
    (acc, item) => ({
      good: acc.good + (item.good ?? 0),
      degraded: acc.degraded + (item.degraded ?? 0),
      insufficient: acc.insufficient + (item.insufficient ?? 0),
    }),
    { good: 0, degraded: 0, insufficient: 0 },
  );
  return `${totals.good} / ${totals.degraded} / ${totals.insufficient}`;
}

function shortValue(value: unknown): string {
  if (typeof value !== 'string' || !value) return 'none';
  return value.length > 24 ? `${value.slice(0, 24)}...` : value;
}

function formatMaybe(value: unknown): string {
  return typeof value === 'number' ? value.toFixed(4) : 'n/a';
}

function metricText(metrics: Record<string, unknown> | undefined, key: string): string {
  const value = metrics?.[key];
  if (typeof value === 'number') return value.toFixed(4);
  if (typeof value === 'string') return value;
  return 'n/a';
}

function quantileText(value?: Record<string, number>): string {
  if (!value) return 'n/a';
  return Object.entries(value)
    .map(([key, numberValue]) => `${key}:${numberValue.toFixed(3)}`)
    .join(' ');
}

function limitationsText(metrics: Record<string, unknown> | undefined): string {
  const limitations = metrics?.limitations;
  if (Array.isArray(limitations)) return limitations.join('; ');
  return 'No model limitations recorded.';
}
