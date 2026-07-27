import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  Archive,
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
};

type Locale = 'en' | 'ru';

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
  lifecycle_status: string;
  dataset_id: string;
  dataset_kind: string;
  threshold: number;
  created_at: string;
};

type MLTrainingRun = {
  training_run_id: string;
  dataset_id: string;
  dataset_kind: string;
  split_id: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
};

type MLScoringRun = {
  scoring_run_id: string;
  model_id: string;
  dataset_id: string;
  status: string;
  window_count: number;
  anomaly_count: number;
  started_at: string;
};

type MLStatus = {
  schema_version: number;
  models: MLModel[];
  champions: MLModel[];
  training_runs: MLTrainingRun[];
  scoring_runs: MLScoringRun[];
  legacy_unregistered: boolean;
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
  },
};

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
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
  const t = copy[locale];

  const refresh = React.useCallback(async () => {
    const statusResponse = await api<{ data: Status }>('/status');
    const anomalyResponse = await api<{ anomalies: Anomaly[] }>('/anomalies');
    const capabilityResponse = await api<{ data: { collectors: CollectorCapability[] } }>(
      '/collectors/capabilities',
    );
    const qualityResponse = await api<{ data: DataQuality }>('/data-quality');
    const mlStatusResponse = await api<{ data: MLStatus }>('/ml/status');
    setStatus(statusResponse.data);
    setAnomalies(anomalyResponse.anomalies);
    setCapabilities(capabilityResponse.data.collectors);
    setDataQuality(qualityResponse.data);
    setMlStatus(mlStatusResponse.data);
  }, []);

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

  const selectedAnomaly = anomalies[selected];
  const scores = anomalies.slice(0, 24).reverse();
  const maxScore = Math.max(...scores.map((item) => item.anomaly_score), 1);
  const champion = mlStatus?.champions[0];
  const recommended = mlStatus?.models.find((model) => model.lifecycle_status === 'recommended');
  const latestTrainingRun = mlStatus?.training_runs[0];
  const latestScoringRun = mlStatus?.scoring_runs[0];

  return (
    <main>
      <header className="topbar">
        <div>
          <h1>{t.title}</h1>
          <p>{t.subtitle}</p>
        </div>
        <button className="iconButton" onClick={() => setLocale(locale === 'en' ? 'ru' : 'en')} title="Language">
          <Languages size={18} />
          {locale.toUpperCase()}
        </button>
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
          <strong>{status?.model.trained ? 'trained' : 'missing'}</strong>
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
        <div className="pipelineActions">
          <button
            onClick={() =>
              run(
                'ml-train',
                () =>
                  api('/ml/train', {
                    method: 'POST',
                    body: JSON.stringify({ dataset_kind: 'synthetic', seed: 42 }),
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
                    () =>
                      api('/ml/drift', {
                        method: 'POST',
                        body: JSON.stringify({
                          dataset_id: champion.dataset_id,
                          model_id: champion.model_id,
                        }),
                      }),
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
        </div>
        <p className="warning">{t.mlWarning}</p>
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
