import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, Database, Languages, Play, Radar, Shield, Sparkles, Square } from 'lucide-react';
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
  storage: { event_count: number; anomaly_count: number; database_path: string };
  model: { trained?: boolean; model_version?: string };
  collection?: CollectionStatus;
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
  const t = copy[locale];

  const refresh = React.useCallback(async () => {
    const statusResponse = await api<{ data: Status }>('/status');
    const anomalyResponse = await api<{ anomalies: Anomaly[] }>('/anomalies');
    const capabilityResponse = await api<{ data: { collectors: CollectorCapability[] } }>('/collectors/capabilities');
    setStatus(statusResponse.data);
    setAnomalies(anomalyResponse.anomalies);
    setCapabilities(capabilityResponse.data.collectors);
  }, []);

  React.useEffect(() => {
    refresh().catch(() => setMessage('Backend is not reachable'));
  }, [refresh]);

  const run = async (label: string, action: () => Promise<unknown>) => {
    setBusy(label);
    try {
      const result = await action();
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
