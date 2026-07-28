export type DatasetKind = 'synthetic' | 'real';
export type Page =
  | 'overview'
  | 'telemetry'
  | 'pipeline'
  | 'ml'
  | 'detection'
  | 'findings'
  | 'runtime';

export type Risk = 'none' | 'low' | 'medium' | 'high' | 'critical';

export type RuntimeBootstrap = {
  version: string;
  mode: string;
  service_mode: boolean;
  control_token?: string | null;
};

export type RuntimeStatus = {
  state: string;
  mode: string;
  port?: number | null;
  version: string;
  config_warning?: string | null;
};

export type ReadyStatus = {
  ready: boolean;
  state: string;
  mode: string;
  frontend_ready: boolean;
  database_ready: boolean;
  data_root_writable: boolean;
};

export type RuntimeBuild = {
  application_version?: string;
  version?: string;
  git_commit?: string;
  build_timestamp_utc?: string;
  mode?: string;
  signed?: boolean;
  frontend_build_hash?: string;
  release_manifest_sha256?: string;
};

export type RuntimeVerification = {
  status: string;
  signed: boolean;
  manifest_sha256?: string;
  checked_files?: number;
  errors?: string[];
};

export type DoctorReport = {
  status: string;
  schema_version: number;
  mode: string;
  checks: Array<Record<string, unknown>>;
};

export type CollectorCapability = {
  collector_id: string;
  status: string;
  required_privilege: string;
  errors: string[];
};

export type CollectionSession = {
  session_id: string;
  started_at: string;
  completed_at?: string | null;
  status: string;
  duration_seconds?: number;
  events_collected?: number;
};

export type CollectionStatus = {
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

export type Status = {
  storage: {
    event_count: number;
    anomaly_count: number;
    quarantine_count?: number;
    feature_window_count?: number;
    model_count?: number;
    scoring_run_count?: number;
  };
  model: { trained?: boolean; model_version?: string };
  collection?: CollectionStatus;
  data_pipeline?: {
    quarantine?: { count: number };
    features?: { windows?: Record<string, Record<string, number>> };
    snapshots?: DatasetSnapshots;
  };
  detection?: DetectionStatus;
};

export type DatasetSnapshot = {
  dataset_id: string;
  dataset_kind?: DatasetKind;
  manifest_sha256: string;
  created_at: string;
  verified_at?: string | null;
  row_count?: number;
};

export type DatasetSnapshots = Record<DatasetKind, DatasetSnapshot[]>;

export type DataQuality = {
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
  dataset_snapshots: DatasetSnapshots;
  collection_progress: CollectionStatus['progress'];
};

export type RetentionPreview = {
  status?: string;
  deletable_counts?: Record<string, number>;
  would_delete?: Record<string, number>;
  blocked_reason?: string;
};

export type TrainingEligibility = {
  eligible?: boolean;
  dataset_kind?: DatasetKind;
  reasons?: string[];
  reason?: string;
  snapshot_ready?: boolean;
  usable_coverage_seconds?: number;
};

export type MLModel = {
  model_id: string;
  family: string;
  model_version: string;
  lifecycle_status: string;
  dataset_id: string;
  dataset_kind: DatasetKind;
  threshold: number;
  created_at: string;
  verified_at?: string | null;
  profile_key?: string;
};

export type MLTrainingRun = {
  training_run_id: string;
  dataset_id: string;
  dataset_kind: DatasetKind;
  split_id: string;
  profile_key: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
  safe_error_message?: string | null;
};

export type MLScoringRun = {
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

export type MLStatus = {
  schema_version: number;
  models: MLModel[];
  champions: MLModel[];
  training_runs: MLTrainingRun[];
  scoring_runs: MLScoringRun[];
  legacy_unregistered: boolean;
  legacy_artifact?: { description: string; recommendation: string };
};

export type MLModelDetails = {
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

export type DriftReport = {
  status: string;
  reference_split?: { count?: number; kind?: string };
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

export type DetectionPolicySummary = {
  policy_id: string;
  policy_version: string;
  policy_hash: string;
  mode: string;
  active: boolean;
};

export type DetectionRule = {
  rule_id: string;
  name?: string;
  enabled: boolean;
  severity?: Risk;
  description?: string;
};

export type DetectionRun = {
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

export type DetectionStatus = {
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

export type DetectionFinding = {
  finding_id: string;
  fingerprint: string;
  dataset_kind: DatasetKind;
  profile_key: string;
  status: string;
  risk_level: Risk;
  detection_score: number;
  primary_signal_id: string;
  title: string;
  summary: string;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
};

export type DetectionFindingDetail = DetectionFinding & {
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

export type DetectionSuppression = {
  suppression_id: string;
  scope: string;
  dataset_kind?: DatasetKind | null;
  profile_key?: string | null;
  finding_fingerprint?: string | null;
  signal_id?: string | null;
  reason: string;
  expires_at: string;
  revoked_at?: string | null;
};

export type DashboardData = {
  bootstrap: RuntimeBootstrap | null;
  ready: ReadyStatus | null;
  runtimeStatus: RuntimeStatus | null;
  build: RuntimeBuild | null;
  verification: RuntimeVerification | null;
  doctor: DoctorReport | null;
  status: Status | null;
  capabilities: CollectorCapability[];
  sessions: CollectionSession[];
  quality: DataQuality | null;
  retention: RetentionPreview | null;
  syntheticEligibility: TrainingEligibility | null;
  realEligibility: TrainingEligibility | null;
  ml: MLStatus | null;
  policies: DetectionPolicySummary[];
  rules: DetectionRule[];
  detection: DetectionStatus | null;
  findings: DetectionFinding[];
  suppressions: DetectionSuppression[];
};
