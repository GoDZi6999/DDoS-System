// Shapes of the API responses the dashboard reads (see docs/API.md).

export type Role = "admin" | "analyst" | "viewer";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "NEW" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";

export type Page<T> = { items: T[]; total: number; limit: number; offset: number };
export type UserRef = { id: number; username: string };

export type User = {
  id: number;
  username: string;
  email: string | null;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
};

export type AlertSummary = {
  id: number;
  status: AlertStatus;
  severity: Severity;
  attack_type: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number | null;
  protocol: string;
  confidence: number;
  risk_score: number;
  detection_count: number;
  first_seen_at: string;
  last_seen_at: string;
  peak_packets_per_sec: number;
  peak_bytes_per_sec: number;
  description: string;
  assigned_to: UserRef | null;
};

export type Factor = { feature: string; value: number; contribution: number; weight: number };

export type AlertDetail = AlertSummary & {
  recommended_action: string;
  explanation: Factor[];
  risk_components: Record<string, number>;
  model_version: string;
  acknowledged_by: UserRef | null;
  acknowledged_at: string | null;
  resolved_at: string | null;
  unique_sources: number;
  allowed_transitions: AlertStatus[];
  wireshark_filter: string;
  evidence_capture_id: number | null;
  notes: { id: number; author: UserRef; body: string; created_at: string }[];
  history: {
    ts: string;
    actor: string;
    action: string;
    before: Record<string, unknown> | null;
    after: Record<string, unknown> | null;
  }[];
};

export type EventSummary = {
  id: number;
  ts: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  label: string;
  confidence: number;
  risk_score: number;
  packets_per_sec: number;
};

export type StatsSummary = {
  window: string;
  events: number;
  attacks: number;
  alerts_open: number;
  alerts_contained: number;
  alerts_by_status: Partial<Record<AlertStatus, number>>;
  open_alerts_by_severity: Partial<Record<Severity, number>>;
  risk_score: number;
  severity: Severity;
};

export type Timeseries = {
  window: string;
  bucket: string;
  points: { ts: string; events: number; attacks: number }[];
};

export type Distribution = { window: string; items: { label: string; count: number }[] };

export type DetectionConfig = {
  alert_min_risk: number;
  aggregation_window_minutes: number;
  risk_weights: {
    ml_confidence: number;
    traffic_anomaly: number;
    attack_severity: number;
    source_reputation: number;
  };
};

export type AuditEntry = {
  id: number;
  ts: string;
  actor_id: number | null;
  actor: string;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  ip: string | null;
  user_agent: string | null;
};

export type TrafficTick = {
  ts: string;
  source_id?: string;
  flows_per_s: number;
  packets_per_s: number;
  attacks: number;
  attacks_per_s?: number;
  max_risk: number;
  active_flows: number;
};

export type LiveMessage =
  | { type: "auth.ok"; user: User }
  | { type: "alert.new" | "alert.updated"; data: AlertSummary }
  | { type: "traffic.tick"; data: TrafficTick };

export type ChannelKind = "email" | "slack" | "webhook";
export type DeliveryStatus = "pending" | "sent" | "failed" | "suppressed";

export type Channel = {
  id: number;
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  min_severity: Severity;
  max_per_hour: number;
  config: { recipients?: string[]; webhook_url?: string; url?: string; secret_set?: boolean };
  created_at: string;
  updated_at: string;
  last_delivery_at: string | null;
  last_delivery_status: DeliveryStatus | null;
};

export type Delivery = {
  id: number;
  channel: { id: number; name: string; kind: ChannelKind };
  alert_id: number | null;
  event: "alert.created" | "alert.escalated" | "test";
  status: DeliveryStatus;
  attempts: number;
  last_error: string | null;
  title: string;
  created_at: string;
  next_attempt_at: string;
  sent_at: string | null;
};

export type SensorStatus = "online" | "stale" | "offline";

export type Sensor = {
  name: string;
  status: SensorStatus;
  hostname: string;
  platform: string;
  interface: string;
  filter: string;
  started_at: string | null;
  last_seen: string | null;
  packets: number;
  packets_per_s: number;
  flows_sent: number;
  flows_buffered: number;
  flows_dropped: number;
  capture_drops: number;
  active_flows: number;
};

export type SensorList = {
  items: Sensor[];
  backlog: { pending: number; lag: number | null } | null;
};

export type CaptureStatus = "queued" | "analyzing" | "done" | "failed";

export type CaptureReport = {
  packets: number;
  flows: number;
  attacks: number;
  attack_types: Record<string, number>;
  /** "model", or the cross-flow rule that raised the detection (e.g. "rule:flood-v1"). */
  detected_by?: Record<string, number>;
  top_sources: { ip: string; detections: number }[];
  top_targets: { target: string; detections: number }[];
  max_risk: number;
  first_packet_at: string;
  last_packet_at: string;
  duration_s: number;
  analysis_s: number;
  model_version: string;
};

export type Capture = {
  id: number;
  filename: string;
  file_format: "pcap" | "pcapng";
  size_bytes: number;
  sha256: string;
  raise_alerts: boolean;
  status: CaptureStatus;
  error: string | null;
  uploaded_by_id: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  report: CaptureReport | null;
};
