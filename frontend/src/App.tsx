import React from 'react';
import {
  Activity,
  Archive,
  Bell,
  CheckCircle2,
  Database,
  FileSearch,
  FlaskConical,
  HeartPulse,
  ListFilter,
  Play,
  RefreshCw,
  RotateCcw,
  Shield,
  Sparkles,
  Square,
  Terminal,
} from 'lucide-react';
import { api, runtimeBootstrap } from './api';
import { Card, ConfirmDialog, EmptyState, ErrorState, LoadingState, Section, Toasts } from './components';
import {
  formatCount,
  formatDate,
  formatDuration,
  formatPercent,
  formatScore,
  jsonPreview,
  maskProfile,
  metricText,
  shortValue,
} from './format';
import type {
  DashboardData,
  DatasetKind,
  DetectionFinding,
  DetectionFindingDetail,
  DetectionPolicySummary,
  DetectionRule,
  DetectionStatus,
  DriftReport,
  MLStatus,
  MLModel,
  MLModelDetails,
  Page,
  ReadyStatus,
  RetentionPreview,
  RuntimeBuild,
  RuntimeStatus,
  RuntimeVerification,
  Status,
  TrainingEligibility,
  DataQuality,
  CollectionSession,
  CollectorCapability,
  DetectionSuppression,
} from './types';

type Toast = { id: number; tone: 'ok' | 'error' | 'info'; text: string };
type ConfirmState = { title: string; body: string; label: string; action: () => Promise<void> };

const pages: Array<{ id: Page; label: string; icon: React.ComponentType<{ size?: number }> }> = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'telemetry', label: 'Telemetry', icon: Shield },
  { id: 'pipeline', label: 'Data Pipeline', icon: Archive },
  { id: 'ml', label: 'ML Lab', icon: Sparkles },
  { id: 'detection', label: 'Detection Center', icon: Bell },
  { id: 'findings', label: 'Findings', icon: FileSearch },
  { id: 'runtime', label: 'Runtime', icon: Terminal },
];

const initialData: DashboardData = {
  bootstrap: null,
  ready: null,
  runtimeStatus: null,
  build: null,
  verification: null,
  doctor: null,
  status: null,
  capabilities: [],
  sessions: [],
  quality: null,
  retention: null,
  syntheticEligibility: null,
  realEligibility: null,
  ml: null,
  policies: [],
  rules: [],
  detection: null,
  findings: [],
  suppressions: [],
};

export function App() {
  const [page, setPage] = React.useState<Page>('overview');
  const [datasetKind, setDatasetKind] = React.useState<DatasetKind>('synthetic');
  const [data, setData] = React.useState<DashboardData>(initialData);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState('');
  const [error, setError] = React.useState('');
  const [toasts, setToasts] = React.useState<Toast[]>([]);
  const [confirm, setConfirm] = React.useState<ConfirmState | null>(null);
  const [selectedDatasetId, setSelectedDatasetId] = React.useState('');
  const [selectedFinding, setSelectedFinding] = React.useState<DetectionFindingDetail | null>(null);
  const [findingStatus, setFindingStatus] = React.useState('all');
  const [findingSeverity, setFindingSeverity] = React.useState('all');
  const [findingSignal, setFindingSignal] = React.useState('');
  const [findingSince, setFindingSince] = React.useState('');
  const [findingUntil, setFindingUntil] = React.useState('');
  const [modelDetails, setModelDetails] = React.useState<MLModelDetails | null>(null);
  const [drift, setDrift] = React.useState<DriftReport | null>(null);
  const [policyHash, setPolicyHash] = React.useState('');

  const notify = React.useCallback((tone: Toast['tone'], text: string) => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((items) => [...items.slice(-3), { id, tone, text }]);
  }, []);

  const refresh = React.useCallback(async () => {
    setError('');
    const query = new URLSearchParams({ dataset_kind: datasetKind });
    if (findingStatus !== 'all') query.set('status', findingStatus);
    const [
      bootstrap,
      ready,
      runtimeStatus,
      build,
      verification,
      status,
      capabilities,
      sessions,
      quality,
      retention,
      syntheticEligibility,
      realEligibility,
      ml,
      detection,
      policies,
      rules,
      findings,
      suppressions,
    ] = await Promise.all([
      runtimeBootstrap(),
      readData<ReadyStatus>('/health/ready'),
      readData<RuntimeStatus>('/runtime/status'),
      readData<RuntimeBuild>('/runtime/build'),
      readData<RuntimeVerification>('/runtime/verify-installation'),
      readData<Status>('/status'),
      readNested<CollectorCapability[], 'collectors'>('/collectors/capabilities', 'collectors', []),
      readNested<CollectionSession[], 'sessions'>('/collection/sessions', 'sessions', []),
      readData<DataQuality>('/data-quality'),
      readData<RetentionPreview>('/retention/preview'),
      postData<TrainingEligibility>('/training/eligibility', { dataset_kind: 'synthetic' }),
      postData<TrainingEligibility>('/training/eligibility', { dataset_kind: 'real' }),
      readData<MLStatus>('/ml/status'),
      readData<DetectionStatus>('/detection/status'),
      readNested<DetectionPolicySummary[], 'policies'>('/detection/policies', 'policies', []),
      readNested<DetectionRule[], 'rules'>('/detection/rules', 'rules', []),
      readNested<DetectionFinding[], 'findings'>(`/detection/findings?${query.toString()}`, 'findings', []),
      readNested<DetectionSuppression[], 'suppressions'>('/detection/suppressions', 'suppressions', []),
    ]);
    const next: DashboardData = {
      bootstrap,
      ready,
      runtimeStatus,
      build,
      verification,
      doctor: data.doctor,
      status,
      capabilities,
      sessions,
      quality,
      retention,
      syntheticEligibility,
      realEligibility,
      ml,
      detection,
      policies,
      rules,
      findings,
      suppressions,
    };
    setData(next);
    if (!policyHash) {
      setPolicyHash(detection?.active_policy?.policy_hash ?? policies[0]?.policy_hash ?? '');
    }
  }, [data.doctor, datasetKind, findingStatus, policyHash]);

  React.useEffect(() => {
    setLoading(true);
    refresh()
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : 'Backend is not reachable');
      })
      .finally(() => setLoading(false));
  }, [refresh]);

  const run = React.useCallback(
    async (label: string, action: () => Promise<unknown>, success = `${label} completed`) => {
      setBusy(label);
      try {
        const result = await action();
        notify('ok', success);
        await refresh();
        return result;
      } catch (reason) {
        const message = reason instanceof Error ? reason.message : `${label} failed`;
        notify('error', message);
        throw reason;
      } finally {
        setBusy('');
      }
    },
    [notify, refresh],
  );

  const ask = (next: ConfirmState) => setConfirm(next);
  const selectedPolicy = policyFromHash(data.policies, policyHash) ?? activePolicy(data.policies);
  const champion = data.ml?.champions[0] ?? null;
  const candidate = data.ml?.models.find((model) =>
    ['recommended', 'candidate'].includes(model.lifecycle_status),
  );
  const datasets = data.quality?.dataset_snapshots[datasetKind] ?? [];
  const effectiveDatasetId = selectedDatasetId || datasets[0]?.dataset_id || '';
  const filteredFindings = filterFindings(
    data.findings,
    findingSeverity,
    findingSignal,
    findingSince,
    findingUntil,
  );

  const actions = makeActions({
    datasetKind,
    effectiveDatasetId,
    selectedPolicy,
    champion,
    candidate,
    selectedFinding,
    setData,
    setDrift,
    setModelDetails,
    setSelectedFinding,
    run,
    ask,
  });

  return (
    <main className="appShell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brandBlock">
          <Shield size={26} />
          <div>
            <strong>SentinelUEBA</strong>
            <span>v{data.bootstrap?.version ?? '0.6.0'}</span>
          </div>
        </div>
        <nav>
          {pages.map((item) => {
            const Icon = item.icon;
            return (
              <button
                type="button"
                key={item.id}
                className={page === item.id ? 'active' : ''}
                onClick={() => setPage(item.id)}
              >
                <Icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </aside>
      <div className="workspace">
        <header className="productHeader">
          <div>
            <h1>{pages.find((item) => item.id === page)?.label ?? 'Overview'}</h1>
            <p>Local product console for collection, datasets, ML, detection and triage.</p>
          </div>
          <div className="headerStatus" aria-label="Runtime summary">
            <span className={data.ready?.ready ? 'pill good' : 'pill warn'}>
              {data.ready?.ready ? 'ready' : data.runtimeStatus?.state ?? 'offline'}
            </span>
            <span className="pill">{data.runtimeStatus?.mode ?? data.bootstrap?.mode ?? 'development'}</span>
            <span className="pill">{data.bootstrap?.service_mode ? 'service mode' : 'desktop/dev mode'}</span>
            <span className="pill">{datasetKind}</span>
            <span className="pill">{maskProfile(champion?.profile_key ?? modelDetails?.model.profile_key)}</span>
          </div>
        </header>

        {busy ? (
          <div className="busyLine" role="status">
            <RefreshCw size={16} className="spin" />
            {busy}
          </div>
        ) : null}
        {loading ? <LoadingState label="Loading SentinelUEBA state" /> : null}
        {error ? <ErrorState title="Dashboard data unavailable" detail={error} onRetry={refresh} /> : null}

        {!loading && !error ? (
          <>
            {page === 'overview' ? (
              <OverviewPage
                data={data}
                actions={actions}
                candidate={candidate}
                setPage={setPage}
              />
            ) : null}
            {page === 'telemetry' ? <TelemetryPage data={data} actions={actions} /> : null}
            {page === 'pipeline' ? (
              <PipelinePage
                data={data}
                datasetKind={datasetKind}
                setDatasetKind={setDatasetKind}
                selectedDatasetId={effectiveDatasetId}
                setSelectedDatasetId={setSelectedDatasetId}
                actions={actions}
              />
            ) : null}
            {page === 'ml' ? (
              <MLLabPage
                data={data}
                datasetKind={datasetKind}
                setDatasetKind={setDatasetKind}
                selectedDatasetId={effectiveDatasetId}
                setSelectedDatasetId={setSelectedDatasetId}
                modelDetails={modelDetails}
                drift={drift}
                actions={actions}
              />
            ) : null}
            {page === 'detection' ? (
              <DetectionPage
                data={data}
                datasetKind={datasetKind}
                setDatasetKind={setDatasetKind}
                policyHash={policyHash}
                setPolicyHash={setPolicyHash}
                actions={actions}
              />
            ) : null}
            {page === 'findings' ? (
              <FindingsPage
                data={data}
                filteredFindings={filteredFindings}
                selectedFinding={selectedFinding}
                filters={{ findingStatus, findingSeverity, findingSignal, findingSince, findingUntil }}
                setFilters={{
                  setFindingStatus,
                  setFindingSeverity,
                  setFindingSignal,
                  setFindingSince,
                  setFindingUntil,
                }}
                actions={actions}
              />
            ) : null}
            {page === 'runtime' ? <RuntimePage data={data} actions={actions} /> : null}
          </>
        ) : null}
      </div>
      <Toasts items={toasts} onDismiss={(id) => setToasts((items) => items.filter((item) => item.id !== id))} />
      {confirm ? (
        <ConfirmDialog
          title={confirm.title}
          body={confirm.body}
          confirmLabel={confirm.label}
          onCancel={() => setConfirm(null)}
          onConfirm={() => {
            const action = confirm.action;
            setConfirm(null);
            action().catch(() => undefined);
          }}
        />
      ) : null}
    </main>
  );
}

function OverviewPage({
  data,
  actions,
  candidate,
  setPage,
}: {
  data: DashboardData;
  candidate?: MLModel | null;
  actions: Actions;
  setPage: (page: Page) => void;
}) {
  const openFindings = data.findings.filter((finding) => finding.status !== 'resolved').length;
  const severeFindings = data.findings.filter((finding) =>
    ['high', 'critical'].includes(finding.risk_level),
  ).length;
  const nextStep = guidedNextStep(data, candidate);
  const latestActions = [
    data.ml?.training_runs[0] ? `Training ${data.ml.training_runs[0].status}` : null,
    data.ml?.scoring_runs[0] ? `Scoring ${data.ml.scoring_runs[0].status}` : null,
    data.detection?.latest_run ? `Detection ${data.detection.latest_run.status}` : null,
    data.findings[0] ? `Finding ${data.findings[0].status}` : null,
  ].filter(Boolean);
  return (
    <>
      <section className="metricGrid">
        <Card label="Host" value={data.runtimeStatus?.state ?? 'offline'} detail={data.runtimeStatus?.mode} tone={data.ready?.ready ? 'good' : 'warn'} />
        <Card label="Events" value={formatCount(data.status?.storage.event_count)} />
        <Card label="Feature windows" value={formatCount(data.status?.storage.feature_window_count)} />
        <Card label="Datasets" value={formatCount(snapshotCount(data))} />
        <Card label="Registered models" value={formatCount(data.ml?.models.length)} />
        <Card label="Champion" value={shortValue(data.ml?.champions[0]?.model_id)} />
        <Card label="Open findings" value={formatCount(openFindings)} tone={openFindings ? 'warn' : 'good'} />
        <Card label="High/Critical" value={formatCount(severeFindings)} tone={severeFindings ? 'bad' : 'good'} />
        <Card label="Collection" value={data.status?.collection?.running ? 'running' : 'stopped'} />
        <Card label="Detection worker" value={data.detection?.worker?.status ?? 'stopped'} />
        <Card label="Real readiness" value={eligibilityText(data.realEligibility)} />
        <Card label="Last action" value={latestActions[0] ?? 'none'} />
      </section>
      <Section title="Guided First Run">
        <div className="flow" data-testid="guided-flow">
          <FlowStep label="1. Generate synthetic demo" active={nextStep === 'generate'} done={(data.status?.storage.event_count ?? 0) > 0} onClick={actions.generateDemo} />
          <FlowStep label="2. Materialize features" active={nextStep === 'features'} done={(data.status?.storage.feature_window_count ?? 0) > 0} onClick={actions.materializeFeatures} />
          <FlowStep label="3. Create dataset" active={nextStep === 'dataset'} done={snapshotCount(data) > 0} onClick={actions.createDataset} />
          <FlowStep label="4. Train models" active={nextStep === 'train'} done={(data.ml?.models.length ?? 0) > 0} onClick={actions.trainModels} />
          <FlowStep label="5. Promote champion" active={nextStep === 'promote'} done={(data.ml?.champions.length ?? 0) > 0} onClick={actions.promoteCandidate} />
          <FlowStep label="6. Run detection" active={nextStep === 'detect'} done={(data.detection?.evaluation_count ?? 0) > 0} onClick={actions.runDetection} />
          <FlowStep label="7. Open findings" active={nextStep === 'findings'} done={data.findings.length > 0} onClick={() => setPage('findings')} />
        </div>
        <p className="hint">Next available step: {nextStep}. The flow uses real local APIs and synthetic data only.</p>
      </Section>
    </>
  );
}

function TelemetryPage({ data, actions }: { data: DashboardData; actions: Actions }) {
  const serviceMode = data.bootstrap?.service_mode;
  const collection = data.status?.collection;
  return (
    <>
      <Section
        title="Collection Control"
        actions={
          <>
            <button type="button" disabled={serviceMode} title={serviceMode ? 'User-session collection is disabled in service mode.' : 'Start collection'} onClick={actions.startCollection}>
              <Play size={16} /> Start
            </button>
            <button type="button" disabled={serviceMode || !collection?.running} title={serviceMode ? 'Service mode cannot control user-session collectors.' : 'Stop collection'} onClick={actions.stopCollection}>
              <Square size={16} /> Stop
            </button>
          </>
        }
      >
        {serviceMode ? (
          <div className="callout warn" data-testid="service-mode-restriction">
            Collection controls are disabled because Windows user-session telemetry is not collected from service mode.
          </div>
        ) : null}
        <div className="metricGrid compact">
          <Card label="Status" value={collection?.running ? 'running' : 'stopped'} />
          <Card label="Active session" value={shortValue(collection?.session_id)} />
          <Card label="Duration" value="manual" detail="Use CLI for scheduled long capture." />
          <Card label="Interval" value="5s default" />
          <Card label="Cumulative" value={formatDuration(collection?.progress.cumulative_collected_seconds)} />
          <Card label="Current" value={formatDuration(collection?.progress.current_session_seconds)} />
          <Card label="Progress to 24h" value={formatPercent(collection?.progress.progress_to_24h)} />
          <Card label="Strict continuous" value={collection?.progress.strict_continuous_24h_validated ? 'validated' : 'not yet'} />
        </div>
      </Section>
      <Section title="Collector Capabilities">
        {data.capabilities.length ? (
          <div className="tileGrid">
            {data.capabilities.map((collector) => (
              <article className="tile" key={collector.collector_id}>
                <strong>{collector.collector_id}</strong>
                <span>{collector.status}</span>
                <small>{collector.required_privilege}</small>
                <small>{collector.errors.join('; ') || 'No safe errors'}</small>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="No collectors reported" detail="Refresh after the local host is ready." />
        )}
      </Section>
      <Section title="Recent Sessions and Event Summary">
        <div className="twoColumn">
          <div className="table">
            {data.sessions.slice(0, 8).map((session) => (
              <button type="button" className="rowButton" key={session.session_id}>
                <span>{shortValue(session.session_id)}</span>
                <span>{session.status}</span>
                <span>{formatDate(session.started_at)}</span>
                <span>{formatCount(session.events_collected)}</span>
              </button>
            ))}
            {!data.sessions.length ? <EmptyState title="No collection sessions" detail="Start a short collection or use synthetic demo data." /> : null}
          </div>
          <div className="tile">
            <strong>Event summary</strong>
            {['authentication', 'process', 'network', 'system_metrics'].map((kind) => (
              <span key={kind}>{kind}: real {formatCount(collection?.event_summary?.real?.[kind])} / synthetic {formatCount(collection?.event_summary?.synthetic?.[kind])}</span>
            ))}
            <p className="hint">Raw payloads are intentionally hidden. Administrator mode may be required for some Windows Security Event Log details.</p>
          </div>
        </div>
      </Section>
    </>
  );
}

function PipelinePage({
  data,
  datasetKind,
  setDatasetKind,
  selectedDatasetId,
  setSelectedDatasetId,
  actions,
}: {
  data: DashboardData;
  datasetKind: DatasetKind;
  setDatasetKind: (kind: DatasetKind) => void;
  selectedDatasetId: string;
  setSelectedDatasetId: (id: string) => void;
  actions: Actions;
}) {
  const snapshots = data.quality?.dataset_snapshots[datasetKind] ?? [];
  return (
    <>
      <Section
        title="Data Quality and Snapshots"
        actions={
          <>
            <Segmented value={datasetKind} onChange={setDatasetKind} />
            <button type="button" onClick={actions.materializeFeatures}><RefreshCw size={16} /> Materialize</button>
            <button type="button" onClick={actions.createDataset}><Database size={16} /> Create dataset</button>
            <button type="button" disabled={!selectedDatasetId} onClick={actions.verifyDataset}><Shield size={16} /> Verify snapshot</button>
          </>
        }
      >
        <div className="metricGrid compact">
          <Card label="Quarantine" value={formatCount(data.quality?.quarantine.count)} />
          <Card label="Feature schema" value={`SQLite v${data.detection?.schema_version ?? 10}`} />
          <Card label="Feature windows" value={formatCount(windowCount(data, datasetKind))} />
          <Card label="Watermark" value={shortValue(data.quality?.watermark[datasetKind])} />
          <Card label="Usable real coverage" value={formatDuration(data.quality?.usable_coverage_seconds)} />
          <Card label="Training eligibility" value={eligibilityText(datasetKind === 'synthetic' ? data.syntheticEligibility : data.realEligibility)} />
        </div>
        <div className="table">
          {snapshots.map((snapshot) => (
            <label className="rowButton" key={snapshot.dataset_id}>
              <input
                type="radio"
                name="dataset"
                checked={selectedDatasetId === snapshot.dataset_id}
                onChange={() => setSelectedDatasetId(snapshot.dataset_id)}
              />
              <span>{shortValue(snapshot.dataset_id)}</span>
              <span>{shortValue(snapshot.manifest_sha256)}</span>
              <span>{formatDate(snapshot.created_at)}</span>
              <span>{snapshot.verified_at ? 'verified' : 'verify before training'}</span>
            </label>
          ))}
          {!snapshots.length ? <EmptyState title="No snapshots" detail="Materialize features, then create a registered dataset snapshot." /> : null}
        </div>
      </Section>
      <Section
        title="Retention"
        actions={
          <>
            <button type="button" onClick={actions.previewRetention}><FileSearch size={16} /> Preview</button>
            <button type="button" className="danger" onClick={actions.applyRetention}><Archive size={16} /> Apply with confirmation</button>
          </>
        }
      >
        <pre>{jsonPreview(data.retention ?? { status: 'not loaded' })}</pre>
      </Section>
    </>
  );
}

function MLLabPage({
  data,
  datasetKind,
  setDatasetKind,
  selectedDatasetId,
  setSelectedDatasetId,
  modelDetails,
  drift,
  actions,
}: {
  data: DashboardData;
  datasetKind: DatasetKind;
  setDatasetKind: (kind: DatasetKind) => void;
  selectedDatasetId: string;
  setSelectedDatasetId: (id: string) => void;
  modelDetails: MLModelDetails | null;
  drift: DriftReport | null;
  actions: Actions;
}) {
  const snapshots = data.quality?.dataset_snapshots[datasetKind] ?? [];
  return (
    <>
      <Section
        title="Training and Champion Lifecycle"
        actions={
          <>
            <Segmented value={datasetKind} onChange={setDatasetKind} />
            <select aria-label="Training dataset" value={selectedDatasetId} onChange={(event) => setSelectedDatasetId(event.target.value)}>
              <option value="">latest verified snapshot</option>
              {snapshots.map((snapshot) => <option key={snapshot.dataset_id} value={snapshot.dataset_id}>{shortValue(snapshot.dataset_id)}</option>)}
            </select>
            <button type="button" onClick={actions.trainModels}><Sparkles size={16} /> Train candidates</button>
          </>
        }
      >
        <div className="metricGrid compact">
          <Card label="Eligibility" value={eligibilityText(datasetKind === 'synthetic' ? data.syntheticEligibility : data.realEligibility)} />
          <Card label="Autoencoder candidates" value={formatCount(data.ml?.models.filter((m) => m.family.includes('autoencoder')).length)} />
          <Card label="Isolation Forest candidates" value={formatCount(data.ml?.models.filter((m) => m.family.includes('isolation')).length)} />
          <Card label="Champion" value={shortValue(data.ml?.champions[0]?.model_id)} />
          <Card label="Scoring runs" value={formatCount(data.ml?.scoring_runs.length)} />
          <Card label="Registry" value={`SQLite v${data.ml?.schema_version ?? 0}`} />
        </div>
        <p className="hint">Training and promotion are manual. Automatic training and automatic promotion are not enabled.</p>
      </Section>
      <Section title="Model Registry">
        <div className="table modelTable">
          {(data.ml?.models ?? []).map((model) => (
            <div className="rowButton" key={model.model_id}>
              <span>{shortValue(model.model_id)}</span>
              <span>{model.family}</span>
              <span>{model.lifecycle_status}</span>
              <span>{model.dataset_kind}</span>
              <span>{formatScore(model.threshold)}</span>
              <button type="button" onClick={() => actions.loadModel(model.model_id)}>Details</button>
              <button type="button" disabled={model.lifecycle_status !== 'candidate'} onClick={() => actions.recommendModel(model)}>Recommend</button>
              <button type="button" disabled={!['candidate', 'recommended'].includes(model.lifecycle_status)} onClick={() => actions.promoteModel(model)}>Promote</button>
              <button type="button" disabled={model.lifecycle_status !== 'retired'} onClick={() => actions.rollbackModel(model)}><RotateCcw size={14} /> Rollback</button>
              <button type="button" disabled={model.lifecycle_status !== 'champion'} onClick={() => actions.scoreModel(model)}>Score</button>
              <button type="button" disabled={model.lifecycle_status !== 'champion'} onClick={() => actions.runDrift(model)}>Drift</button>
            </div>
          ))}
          {!(data.ml?.models.length ?? 0) ? <EmptyState title="No registered models" detail="Create a dataset and train Autoencoder/Isolation Forest candidates." /> : null}
        </div>
      </Section>
      <div className="twoColumn">
        <Section title="Model Details">
          {modelDetails ? (
            <div className="detailList">
              <span>Family: {modelDetails.model.family}</span>
              <span>Lifecycle: {modelDetails.model.lifecycle_status}</span>
              <span>Profile: {maskProfile(modelDetails.model.profile_key)}</span>
              <span>Verified: {modelDetails.verification?.verified ? 'yes' : 'pending or failed'}</span>
              <span>Scenario recall: {metricText(modelDetails.evaluation?.metrics, 'scenario_recall')}</span>
              <span>False positive rate: {metricText(modelDetails.evaluation?.metrics, 'false_positive_rate')}</span>
              <span>PR-AUC: {metricText(modelDetails.evaluation?.metrics, 'pr_auc')}</span>
            </div>
          ) : <EmptyState title="No model selected" detail="Open details from the registry." />}
        </Section>
        <Section title="Drift">
          {drift ? (
            <div className="detailList">
              <span>Status: {drift.status}</span>
              <span>Reference flagged: {formatScore(drift.reference_flagged_rate)}</span>
              <span>Target flagged: {formatScore(drift.target_flagged_rate)}</span>
              <span>Difference: {formatScore(drift.flagged_rate_difference)}</span>
              {(drift.top_shifted_features ?? []).slice(0, 5).map((feature) => (
                <span key={feature.feature_name}>{feature.feature_name}: shift {formatScore(feature.standardized_mean_shift)}, PSI {formatScore(feature.psi)}</span>
              ))}
            </div>
          ) : <EmptyState title="No drift report" detail="Run drift for the champion model." />}
        </Section>
      </div>
    </>
  );
}

function DetectionPage({
  data,
  datasetKind,
  setDatasetKind,
  policyHash,
  setPolicyHash,
  actions,
}: {
  data: DashboardData;
  datasetKind: DatasetKind;
  setDatasetKind: (kind: DatasetKind) => void;
  policyHash: string;
  setPolicyHash: (hash: string) => void;
  actions: Actions;
}) {
  const latest = data.detection?.latest_run;
  return (
    <>
      <Section
        title="Policy and Execution"
        actions={
          <>
            <Segmented value={datasetKind} onChange={setDatasetKind} />
            <select aria-label="Detection policy" value={policyHash} onChange={(event) => setPolicyHash(event.target.value)}>
              {data.policies.map((policy) => <option key={policy.policy_hash} value={policy.policy_hash}>{policy.policy_id} / {policy.mode}</option>)}
            </select>
            <button type="button" onClick={actions.runDetection}><Play size={16} /> Run once</button>
            <button type="button" onClick={actions.dryRunDetection}><FlaskConical size={16} /> Dry-run</button>
            <button type="button" onClick={actions.backfillDetection}><Archive size={16} /> Exact snapshot backfill</button>
          </>
        }
      >
        <div className="metricGrid compact">
          <Card label="Active policy" value={data.detection?.active_policy.policy_id ?? 'none'} />
          <Card label="Policy mode" value={data.detection?.active_policy.mode ?? 'none'} />
          <Card label="Fusion" value={data.detection?.active_policy.fusion_method ?? 'none'} />
          <Card label="Model signals" value={data.ml?.champions.length ? 'champion available' : 'rules only'} />
          <Card label="Evaluated windows" value={formatCount(data.detection?.evaluation_count)} />
          <Card label="Findings" value={formatCount(Object.values(data.detection?.finding_counts ?? {}).reduce((a, b) => a + b, 0))} />
          <Card label="Suppressed" value={formatCount(data.suppressions.filter((item) => !item.revoked_at).length)} />
          <Card label="No-op" value={formatCount(latest?.no_op_count)} />
        </div>
        <p className="hint">Fusion explanation is deterministic: enabled rules, verified champion model signal when available, policy threshold and finding fingerprint are recorded for audit.</p>
      </Section>
      <Section
        title="Worker"
        actions={
          <>
            <button type="button" onClick={actions.startWorker}><Play size={16} /> Start worker</button>
            <button type="button" onClick={actions.stopWorker}><Square size={16} /> Stop worker</button>
          </>
        }
      >
        <div className="metricGrid compact">
          <Card label="Worker status" value={data.detection?.worker?.status ?? 'stopped'} />
          <Card label="Lease" value={data.detection?.worker?.lease_expired ? 'expired' : 'current or none'} />
          <Card label="Heartbeat" value={formatDate(data.detection?.worker?.heartbeat_at)} />
          <Card label="Latest run" value={latest ? `${latest.status} ${latest.finding_count}/${latest.evaluated_count}` : 'none'} />
        </div>
      </Section>
      <Section title="Rules">
        <div className="tileGrid">
          {(data.rules.length ? data.rules : data.detection?.active_policy.rules ?? []).map((rule) => (
            <article className="tile" key={rule.rule_id}>
              <strong>{rule.rule_id}</strong>
              <span>{rule.enabled ? 'enabled' : 'disabled'}</span>
              <small>{'severity' in rule && typeof rule.severity === 'string' ? rule.severity : 'policy controlled'}</small>
            </article>
          ))}
        </div>
      </Section>
    </>
  );
}

function FindingsPage({
  data,
  filteredFindings,
  selectedFinding,
  filters,
  setFilters,
  actions,
}: {
  data: DashboardData;
  filteredFindings: DetectionFinding[];
  selectedFinding: DetectionFindingDetail | null;
  filters: {
    findingStatus: string;
    findingSeverity: string;
    findingSignal: string;
    findingSince: string;
    findingUntil: string;
  };
  setFilters: {
    setFindingStatus: (value: string) => void;
    setFindingSeverity: (value: string) => void;
    setFindingSignal: (value: string) => void;
    setFindingSince: (value: string) => void;
    setFindingUntil: (value: string) => void;
  };
  actions: Actions;
}) {
  return (
    <>
      <Section title="Finding Filters" actions={<ListFilter size={18} />}>
        <div className="filters">
          <label>Status<select value={filters.findingStatus} onChange={(event) => setFilters.setFindingStatus(event.target.value)}><option value="all">all</option><option value="open">open</option><option value="acknowledged">acknowledged</option><option value="investigating">investigating</option><option value="resolved">resolved</option><option value="false_positive">false positive</option></select></label>
          <label>Severity<select value={filters.findingSeverity} onChange={(event) => setFilters.setFindingSeverity(event.target.value)}><option value="all">all</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></label>
          <label>Signal/rule<input value={filters.findingSignal} onChange={(event) => setFilters.setFindingSignal(event.target.value)} placeholder="rare-process-v1" /></label>
          <label>Since<input value={filters.findingSince} onChange={(event) => setFilters.setFindingSince(event.target.value)} placeholder="2026-07-28T00:00:00Z" /></label>
          <label>Until<input value={filters.findingUntil} onChange={(event) => setFilters.setFindingUntil(event.target.value)} placeholder="2026-07-28T23:59:59Z" /></label>
        </div>
      </Section>
      <div className="twoColumn wideLeft">
        <Section title="Findings">
          <div className="table findingsTable">
            {filteredFindings.map((finding) => (
              <button type="button" className="rowButton" key={finding.finding_id} onClick={() => actions.loadFinding(finding.finding_id)}>
                <span className={`risk ${finding.risk_level}`}>{finding.risk_level}</span>
                <span>{formatScore(finding.detection_score)}</span>
                <span>{finding.status}</span>
                <span>{finding.primary_signal_id}</span>
                <span>{maskProfile(finding.profile_key)}</span>
                <span>{formatDate(finding.first_seen_at)}</span>
                <span>{formatDate(finding.last_seen_at)}</span>
                <span>{formatCount(finding.occurrence_count)}</span>
              </button>
            ))}
            {!filteredFindings.length ? <EmptyState title="No findings match filters" detail="Run detection or relax filters." /> : null}
          </div>
        </Section>
        <Section title="Finding Detail">
          {selectedFinding ? (
            <div className="findingDetail">
              <h3>{selectedFinding.title}</h3>
              <p>{selectedFinding.summary}</p>
              <div className="detailList">
                <span>Status: {selectedFinding.status}</span>
                <span>Score: {formatScore(selectedFinding.detection_score)}</span>
                <span>Rule/model signal: {selectedFinding.primary_signal_id}</span>
                <span>Policy/model identity: {shortValue(selectedFinding.fingerprint)}</span>
                <span>Occurrences: {formatCount(selectedFinding.occurrence_count)}</span>
              </div>
              <div className="buttonRow">
                <button type="button" disabled={selectedFinding.status !== 'open'} onClick={() => actions.transitionFinding('acknowledge')}>Acknowledge</button>
                <button type="button" disabled={!['open', 'acknowledged'].includes(selectedFinding.status)} onClick={() => actions.transitionFinding('investigate')}>Investigating</button>
                <button type="button" disabled={selectedFinding.status === 'resolved'} onClick={() => actions.transitionFinding('resolve')}>Resolve</button>
                <button type="button" onClick={actions.createSuppression}>Create suppression</button>
              </div>
              <h4>Numeric evidence and decisions</h4>
              <pre>{jsonPreview(selectedFinding.occurrences?.[0]?.decision ?? selectedFinding.occurrences?.[0]?.evidence ?? {})}</pre>
              <h4>Occurrence history</h4>
              {(selectedFinding.occurrences ?? []).slice(0, 8).map((occurrence) => (
                <span className="historyLine" key={occurrence.occurrence_id}>{formatDate(occurrence.window_start)} / {occurrence.status} / {occurrence.matched_signal_ids?.join(', ')}</span>
              ))}
              <h4>Lifecycle history</h4>
              {(selectedFinding.history ?? []).slice(0, 8).map((item) => (
                <span className="historyLine" key={item.history_id}>
                  {formatDate(item.created_at)}: {item.from_status} {'->'} {item.to_status}
                </span>
              ))}
            </div>
          ) : (
            <EmptyState title="No finding selected" detail="Open a finding to inspect signals, lifecycle and suppression state." />
          )}
        </Section>
      </div>
      <Section title="Suppressions">
        <div className="table">
          {data.suppressions.map((suppression) => (
            <div className="rowButton" key={suppression.suppression_id}>
              <span>{shortValue(suppression.suppression_id)}</span>
              <span>{suppression.scope}</span>
              <span>{suppression.dataset_kind ?? 'any'}</span>
              <span>{suppression.signal_id ?? shortValue(suppression.finding_fingerprint)}</span>
              <span>{suppression.revoked_at ? 'revoked' : 'active'}</span>
              <button type="button" disabled={Boolean(suppression.revoked_at)} onClick={() => actions.revokeSuppression(suppression.suppression_id)}>Revoke</button>
            </div>
          ))}
          {!data.suppressions.length ? <EmptyState title="No suppressions" detail="Create one from a finding after confirming scope and TTL." /> : null}
        </div>
      </Section>
    </>
  );
}

function RuntimePage({ data, actions }: { data: DashboardData; actions: Actions }) {
  return (
    <>
      <section className="metricGrid">
        <Card label="Application version" value={data.bootstrap?.version ?? data.runtimeStatus?.version ?? '0.6.0'} />
        <Card label="Build commit" value={shortValue(data.build?.git_commit, 12)} />
        <Card label="Build timestamp" value={formatDate(data.build?.build_timestamp_utc)} />
        <Card label="Mode" value={data.build?.mode ?? data.runtimeStatus?.mode ?? 'development'} />
        <Card label="Signed" value={data.build?.signed ? 'signed' : 'unsigned technical preview'} />
        <Card label="Verification" value={data.verification?.status ?? 'not checked'} />
        <Card label="Host state" value={data.runtimeStatus?.state ?? 'unknown'} />
        <Card label="Runtime mode" value={data.bootstrap?.service_mode ? 'service' : 'desktop/development'} />
        <Card label="Database schema" value={`v${data.doctor?.schema_version ?? data.detection?.schema_version ?? 10}`} />
        <Card label="Frontend hash" value={shortValue(data.build?.frontend_build_hash)} />
        <Card label="Doctor" value={data.doctor?.status ?? 'not run'} />
        <Card label="Config warning" value={data.runtimeStatus?.config_warning ? 'present' : 'none'} />
      </section>
      <Section
        title="Runtime Actions"
        actions={
          <>
            <button type="button" onClick={actions.verifyInstallation}><Shield size={16} /> Verify installation</button>
            <button type="button" onClick={actions.runDoctor}><HeartPulse size={16} /> Run doctor</button>
            <button type="button" disabled title="Use the launcher menu or CLI to open the logs location without exposing local paths.">Open logs location</button>
            <button type="button" disabled={data.bootstrap?.service_mode} title={data.bootstrap?.service_mode ? 'Exit is disabled in service mode.' : 'Exit local desktop host'} onClick={actions.shutdown}><Square size={16} /> Exit local application</button>
          </>
        }
      >
        <p className="hint">Control token, absolute paths, username and hostname are intentionally not rendered.</p>
        <pre>{jsonPreview({ verification: data.verification, doctor: data.doctor })}</pre>
      </Section>
    </>
  );
}

function FlowStep({ label, active, done, onClick }: { label: string; active: boolean; done: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`flowStep ${active ? 'active' : ''} ${done ? 'done' : ''}`} onClick={onClick}>
      {done ? <CheckCircle2 size={16} /> : <span className="stepDot" />}
      {label}
    </button>
  );
}

function Segmented({ value, onChange }: { value: DatasetKind; onChange: (value: DatasetKind) => void }) {
  return (
    <div className="segmented" role="group" aria-label="Dataset kind">
      <button type="button" className={value === 'synthetic' ? 'active' : ''} onClick={() => onChange('synthetic')}>synthetic</button>
      <button type="button" className={value === 'real' ? 'active' : ''} onClick={() => onChange('real')}>real</button>
    </div>
  );
}

type Actions = ReturnType<typeof makeActions>;

function makeActions({
  datasetKind,
  effectiveDatasetId,
  selectedPolicy,
  champion,
  candidate,
  selectedFinding,
  setData,
  setDrift,
  setModelDetails,
  setSelectedFinding,
  run,
  ask,
}: {
  datasetKind: DatasetKind;
  effectiveDatasetId: string;
  selectedPolicy?: DetectionPolicySummary;
  champion: MLModel | null;
  candidate?: MLModel | null;
  selectedFinding: DetectionFindingDetail | null;
  setData: React.Dispatch<React.SetStateAction<DashboardData>>;
  setDrift: (report: DriftReport | null) => void;
  setModelDetails: (details: MLModelDetails | null) => void;
  setSelectedFinding: (finding: DetectionFindingDetail | null) => void;
  run: (label: string, action: () => Promise<unknown>, success?: string) => Promise<unknown>;
  ask: (state: ConfirmState) => void;
}) {
  return {
    generateDemo: () => run('generate synthetic demo', () => api('/demo/generate', { method: 'POST', body: JSON.stringify({ seed: 42 }) }), 'Synthetic demo generated'),
    materializeFeatures: () => run('materialize features', () => api('/features/materialize', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind }) }), 'Feature windows materialized'),
    createDataset: () => run('create dataset', () => api('/datasets', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind }) }), 'Dataset snapshot created'),
    verifyDataset: () => run('verify dataset', () => api(`/datasets/${effectiveDatasetId}/verify`, { method: 'POST' }), 'Dataset verified'),
    previewRetention: () => run('retention preview', async () => {
      const response = await api<{ data: RetentionPreview }>('/retention/preview');
      setData((current) => ({ ...current, retention: response.data }));
      return response;
    }, 'Retention preview loaded'),
    applyRetention: () => ask({
      title: 'Apply retention policy?',
      body: 'This deletes expired local records according to the configured retention contract. Dataset/model artifacts are not silently removed.',
      label: 'Apply retention',
      action: () => run('retention apply', () => api('/retention/apply', { method: 'POST', body: JSON.stringify({ confirm: true }) }), 'Retention applied').then(() => undefined),
    }),
    startCollection: () => run('start collection', () => api('/collection/start', { method: 'POST', body: JSON.stringify({ interval_seconds: 5 }) }), 'Collection started'),
    stopCollection: () => run('stop collection', () => api('/collection/stop', { method: 'POST' }), 'Collection stopped'),
    trainModels: () => run('train models', () => api('/ml/train', {
      method: 'POST',
      body: JSON.stringify({
        dataset_kind: datasetKind,
        dataset_id: effectiveDatasetId || undefined,
        seed: 42,
        families: ['autoencoder', 'isolation-forest'],
        autoencoder: { epochs: 12, batch_size: 16, learning_rate: 0.005, weight_decay: 0.0001, hidden_dim: 10, latent_dim: 4, plateau_patience: 8 },
        isolation_forest: { n_estimators: 24, max_samples: 'auto', max_features: 1, bootstrap: false, n_jobs: 1 },
      }),
    }), 'Training completed'),
    loadModel: (modelId: string) => run('load model', async () => {
      const response = await api<{ data: MLModelDetails }>(`/ml/models/${modelId}`);
      setModelDetails(response.data);
      return response;
    }, 'Model details loaded'),
    recommendModel: (model: MLModel) => ask({
      title: 'Recommend candidate?',
      body: `${shortValue(model.model_id)} becomes the recommended candidate, but not champion.`,
      label: 'Recommend',
      action: () => run('recommend model', () => api(`/ml/models/${model.model_id}/recommend`, { method: 'POST', body: JSON.stringify({ confirm: true, reason: 'Dashboard recommendation' }) }), 'Model recommended').then(() => undefined),
    }),
    promoteCandidate: () => {
      if (!candidate) return Promise.reject(new Error('No candidate or recommended model is available'));
      return new Promise<void>((resolve) => {
        ask({
          title: 'Promote champion?',
          body: `${shortValue(candidate.model_id)} becomes champion. Existing champion for the profile is retired.`,
          label: 'Promote',
          action: () => run('promote model', () => api(`/ml/models/${candidate.model_id}/promote`, { method: 'POST', body: JSON.stringify({ confirm: true, reason: 'Guided flow promotion' }) }), 'Champion promoted').then(() => resolve()),
        });
      });
    },
    promoteModel: (model: MLModel) => ask({
      title: 'Promote champion?',
      body: `${shortValue(model.model_id)} becomes champion. Existing champion for the profile is retired.`,
      label: 'Promote',
      action: () => run('promote model', () => api(`/ml/models/${model.model_id}/promote`, { method: 'POST', body: JSON.stringify({ confirm: true, reason: 'Dashboard promotion' }) }), 'Champion promoted').then(() => undefined),
    }),
    rollbackModel: (model: MLModel) => ask({
      title: 'Rollback champion?',
      body: `${shortValue(model.model_id)} becomes champion again and the current champion is retired.`,
      label: 'Rollback',
      action: () => run('rollback model', () => api(`/ml/models/${model.model_id}/rollback`, { method: 'POST', body: JSON.stringify({ confirm: true, reason: 'Dashboard rollback' }) }), 'Rollback completed').then(() => undefined),
    }),
    scoreModel: (model = champion) => run('score model', () => api('/ml/score', { method: 'POST', body: JSON.stringify({ dataset_id: model?.dataset_id, model_id: model?.model_id, dataset_kind: model?.dataset_kind, batch_size: 128 }) }), 'Scoring completed'),
    runDrift: (model = champion) => run('drift report', async () => {
      const response = await api<{ data: DriftReport }>('/ml/drift', { method: 'POST', body: JSON.stringify({ dataset_id: model?.dataset_id, model_id: model?.model_id }) });
      setDrift(response.data);
      return response;
    }, 'Drift report loaded'),
    runDetection: () => run('run detection', () => api('/detection/run-once', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind, policy_id: selectedPolicy?.policy_id, policy_version: selectedPolicy?.policy_version }) }), 'Detection completed'),
    dryRunDetection: () => run('detection dry-run', () => api('/detection/run-once', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind, policy_id: selectedPolicy?.policy_id, policy_version: selectedPolicy?.policy_version, dry_run: true }) }), 'Dry-run completed'),
    backfillDetection: () => ask({
      title: 'Run exact snapshot backfill?',
      body: 'Backfill reads the selected registered snapshot and preserves Detection Engine semantics. Confirm only for intentional historical processing.',
      label: 'Backfill',
      action: () => run('detection backfill', () => api('/detection/backfill', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind, dataset_id: effectiveDatasetId || undefined, policy_id: selectedPolicy?.policy_id, policy_version: selectedPolicy?.policy_version, confirm: true }) }), 'Backfill completed').then(() => undefined),
    }),
    startWorker: () => run('start worker', () => api('/detection/worker/start', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind, interval_seconds: 60, max_windows: 256 }) }), 'Worker started'),
    stopWorker: () => ask({
      title: 'Stop detection worker?',
      body: 'The worker stops gracefully after the current lease cycle.',
      label: 'Stop worker',
      action: () => run('stop worker', () => api('/detection/worker/stop', { method: 'POST', body: JSON.stringify({ dataset_kind: datasetKind, confirm: true }) }), 'Worker stopped').then(() => undefined),
    }),
    loadFinding: (findingId: string) => run('load finding', async () => {
      const response = await api<{ data: DetectionFindingDetail }>(`/detection/findings/${findingId}`);
      setSelectedFinding(response.data);
      return response;
    }, 'Finding loaded'),
    transitionFinding: (verb: 'acknowledge' | 'investigate' | 'resolve') => {
      if (!selectedFinding) return Promise.reject(new Error('Select a finding first'));
      const endpoint = verb === 'investigate' ? 'investigate' : verb;
      return ask({
        title: `${verb} finding?`,
        body: `Finding ${shortValue(selectedFinding.finding_id)} moves to ${verb === 'resolve' ? 'resolved' : verb}.`,
        label: verb,
        action: () => run('finding lifecycle', () => api(`/detection/findings/${selectedFinding.finding_id}/${endpoint}`, { method: 'POST', body: JSON.stringify({ confirm: verb === 'resolve', reason: `Dashboard ${verb}` }) }), 'Finding status updated').then(async () => {
          const response = await api<{ data: DetectionFindingDetail }>(`/detection/findings/${selectedFinding.finding_id}`);
          setSelectedFinding(response.data);
        }),
      });
    },
    createSuppression: () => {
      if (!selectedFinding) return Promise.reject(new Error('Select a finding first'));
      return ask({
        title: 'Create suppression?',
        body: `Suppress signal ${selectedFinding.primary_signal_id} for ${selectedFinding.dataset_kind} for 60 minutes. This is audited and can be revoked.`,
        label: 'Create suppression',
        action: () => run('create suppression', () => api('/detection/suppressions', { method: 'POST', body: JSON.stringify({ scope: 'signal_for_dataset_kind', dataset_kind: selectedFinding.dataset_kind, signal_id: selectedFinding.primary_signal_id, ttl_minutes: 60, reason: 'Dashboard suppression' }) }), 'Suppression created').then(() => undefined),
      });
    },
    revokeSuppression: (suppressionId: string) => ask({
      title: 'Revoke suppression?',
      body: `${shortValue(suppressionId)} will stop suppressing future evaluations.`,
      label: 'Revoke',
      action: () => run('revoke suppression', () => api(`/detection/suppressions/${suppressionId}/revoke`, { method: 'POST', body: JSON.stringify({ confirm: true }) }), 'Suppression revoked').then(() => undefined),
    }),
    verifyInstallation: () => run('verify installation', async () => {
      const response = await api<{ data: DashboardData['verification'] }>('/runtime/verify-installation');
      setData((current) => ({ ...current, verification: response.data }));
      return response;
    }, 'Installation verified'),
    runDoctor: () => run('run doctor', async () => {
      const response = await api<{ data: DashboardData['doctor'] }>('/runtime/doctor');
      setData((current) => ({ ...current, doctor: response.data }));
      return response;
    }, 'Doctor completed'),
    shutdown: () => ask({
      title: 'Exit local application?',
      body: 'This only stops the desktop host. It is disabled in service mode.',
      label: 'Exit',
      action: () => run('shutdown', () => api('/runtime/shutdown', { method: 'POST', body: JSON.stringify({ confirm: true }) }), 'Shutdown requested').then(() => undefined),
    }),
  };
}

async function readData<T>(path: string): Promise<T | null> {
  const response = await api<{ data: T }>(path);
  return response.data;
}

async function postData<T>(path: string, body: unknown): Promise<T | null> {
  const response = await api<{ data: T }>(path, { method: 'POST', body: JSON.stringify(body) });
  return response.data;
}

async function readNested<T, K extends string>(path: string, key: K, fallback: T): Promise<T> {
  const response = await api<{ data: Record<K, T> }>(path);
  return response.data[key] ?? fallback;
}

function activePolicy(policies: DetectionPolicySummary[]): DetectionPolicySummary | undefined {
  return policies.find((policy) => policy.active) ?? policies[0];
}

function policyFromHash(policies: DetectionPolicySummary[], hash: string): DetectionPolicySummary | undefined {
  return policies.find((policy) => policy.policy_hash === hash);
}

function snapshotCount(data: DashboardData): number {
  return (
    (data.quality?.dataset_snapshots.synthetic.length ?? 0) +
    (data.quality?.dataset_snapshots.real.length ?? 0)
  );
}

function windowCount(data: DashboardData, kind: DatasetKind): number {
  const windows = data.status?.data_pipeline?.features?.windows?.[kind] ?? data.quality?.window_quality?.[kind];
  return Object.values(windows ?? {}).reduce((total, value) => total + Number(value ?? 0), 0);
}

function eligibilityText(value: TrainingEligibility | null | undefined): string {
  if (!value) return 'unknown';
  if (value.eligible || value.snapshot_ready) return 'ready';
  return value.reason ?? value.reasons?.join('; ') ?? 'not ready';
}

function guidedNextStep(data: DashboardData, candidate?: MLModel | null): string {
  if ((data.status?.storage.event_count ?? 0) === 0) return 'generate';
  if ((data.status?.storage.feature_window_count ?? 0) === 0) return 'features';
  if (snapshotCount(data) === 0) return 'dataset';
  if ((data.ml?.models.length ?? 0) === 0) return 'train';
  if (!data.ml?.champions.length && candidate) return 'promote';
  if ((data.detection?.evaluation_count ?? 0) === 0) return 'detect';
  return 'findings';
}

function filterFindings(
  findings: DetectionFinding[],
  severity: string,
  signal: string,
  since: string,
  until: string,
): DetectionFinding[] {
  return findings.filter((finding) => {
    if (severity !== 'all' && finding.risk_level !== severity) return false;
    if (signal && !finding.primary_signal_id.toLowerCase().includes(signal.toLowerCase())) return false;
    if (since && new Date(finding.last_seen_at) < new Date(since)) return false;
    if (until && new Date(finding.first_seen_at) > new Date(until)) return false;
    return true;
  });
}
