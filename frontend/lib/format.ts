// Display helpers: plain-language names for model features and attack labels.

const ATTACKS: Record<string, string> = {
  benign: "Benign",
  ddos: "DDoS",
  dos: "DoS",
  portscan: "Port scan",
  bruteforce: "Brute force",
  webattack: "Web attack",
  botnet: "Botnet",
};

export function attackName(label: string): string {
  return ATTACKS[label] ?? label.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

// Mirrors ml/sentinel_ml/features.py (client = forward, server = backward).
const FEATURES: Record<string, string> = {
  flow_duration_s: "Flow duration",
  fwd_packets: "Packets from client",
  bwd_packets: "Packets from server",
  fwd_bytes: "Bytes from client",
  bwd_bytes: "Bytes from server",
  fwd_pkt_len_max: "Largest client packet",
  fwd_pkt_len_min: "Smallest client packet",
  fwd_pkt_len_mean: "Average client packet size",
  fwd_pkt_len_std: "Client packet size spread",
  bwd_pkt_len_max: "Largest server packet",
  bwd_pkt_len_min: "Smallest server packet",
  bwd_pkt_len_mean: "Average server packet size",
  bwd_pkt_len_std: "Server packet size spread",
  flow_bytes_per_s: "Bytes per second",
  flow_packets_per_s: "Packets per second",
  flow_iat_mean: "Average gap between packets",
  flow_iat_std: "Gap between packets, spread",
  flow_iat_max: "Longest gap between packets",
  flow_iat_min: "Shortest gap between packets",
  fwd_iat_total: "Client gaps, total",
  fwd_iat_mean: "Average gap between client packets",
  bwd_iat_total: "Server gaps, total",
  bwd_iat_mean: "Average gap between server packets",
  fwd_psh_flags: "Client packets with PSH",
  fin_flag_count: "Packets with FIN",
  syn_flag_count: "Packets with SYN",
  rst_flag_count: "Packets with RST",
  psh_flag_count: "Packets with PSH",
  ack_flag_count: "Packets with ACK",
  urg_flag_count: "Packets with URG",
  init_win_bytes_fwd: "Client initial TCP window",
  init_win_bytes_bwd: "Server initial TCP window",
  pkt_len_mean: "Average packet size",
  pkt_len_std: "Packet size spread",
  down_up_ratio: "Server/client packet ratio",
  active_mean: "Average active period",
  idle_mean: "Average idle period",
  window_distinct_ports_src_to_dst: "Distinct ports probed in 10 s",
  beacon_interval_jitter: "Beacon rhythm jitter (0 = perfectly regular)",
  beacon_interval_s: "Seconds between beacons",
  beacon_flows: "Beacons in 5 min",
};

export function featureName(feature: string): string {
  return FEATURES[feature] ?? feature.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export const RISK_COMPONENTS: Record<string, string> = {
  ml_confidence: "Model confidence",
  traffic_anomaly: "Traffic anomaly",
  attack_severity: "Attack severity",
  source_reputation: "Source reputation",
};

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const whole = new Intl.NumberFormat("en");

export function formatCount(value: number): string {
  return Math.abs(value) >= 10_000 ? compact.format(value) : whole.format(Math.round(value));
}

export function formatRate(value: number, unit: string): string {
  return unit ? `${formatCount(value)} ${unit}/s` : `${formatCount(value)}/s`;
}

export function formatBytesRate(value: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000;
    i++;
  }
  return `${value.toFixed(value >= 100 || i === 0 ? 0 : 1)} ${units[i]}/s`;
}

export function formatPercent(fraction: number): string {
  return `${(fraction * 100).toFixed(1)}%`;
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function timeAgo(iso: string, now = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export function target(ip: string, port: number | null): string {
  if (port === null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}
