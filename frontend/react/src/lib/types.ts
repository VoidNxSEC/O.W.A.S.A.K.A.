import type { LucideIcon } from 'lucide-react';

export type AccentName = 'violet' | 'emerald' | 'amber' | 'blue' | 'cyan' | 'slate';

export type SystemLayer = {
  name: string;
  detail: string;
  icon: LucideIcon;
  accent: AccentName;
};

export type FingerprintRecord = {
  label: string;
  value: string;
  icon: LucideIcon;
};

export type EvidenceStep = {
  label: string;
  description: string;
};

export type ConsoleStat = {
  label: string;
  value: string;
  hint: string;
};

export type ProcessorStats = {
  buffered_events: number;
  dropped_events: number;
  backpressure_policy: string;
  top_ips_5m: Array<{
    ip: string;
    count_1m: number;
    count_5m: number;
    count_15m: number;
    rate_1m: number;
  }>;
};

export type TopologyGraph = {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    os?: string;
    ports?: number[];
  }>;
  links: Array<{
    source: string;
    target: string;
    count: number;
  }>;
};

export type HealthPayload = {
  status?: string;
  overall?: string;
  required?: string;
  probes?: Record<string, unknown> | unknown[];
};

export type STHPayload = {
  tree_size: number;
  root_hash: string;
  timestamp_ns: number;
  signature: string;
  signer_key_id: string;
};

export type Incident = {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'triage' | 'containment' | 'collection' | 'recovery';
  source: string;
  target: string;
  updatedAt: string;
};

export type TransparencyEntry = {
  id: string;
  treeSize: number;
  rootHash: string;
  signedAt: string;
  verifier: string;
  status: 'verified' | 'pending' | 'failed';
};

export type LiveEvent = {
  id: string;
  type: 'THREAT_ALERT' | 'DNS' | 'PORT_SCAN' | 'ARP' | 'SYSTEM' | string;
  source: string;
  target: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  time: string;
  summary: string;
  raw?: unknown;
};

export type SensorSurface = {
  name: string;
  coverage: number;
  status: 'online' | 'degraded' | 'offline';
};

export type ResponseAction = {
  label: string;
  count: string;
  tone: 'active' | 'warning' | 'calm' | 'muted';
};
