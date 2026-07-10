export type EventType =
  | 'DNS'
  | 'PORT_SCAN'
  | 'ARP'
  | 'PHYSICAL'
  | 'THREAT_ALERT'
  | 'PROXY'
  | 'VM'
  | 'TOR'
  | 'CANARY'
  | 'COMPLIANCE';

export interface NetworkEvent {
  id: string;
  type: EventType;
  source: string;
  destination?: string;
  metadata: Record<string, unknown>;
  timestamp: string;
}

export type AlertStatus = 'NEW' | 'TRIAGING' | 'CONTAINED' | 'CLOSED';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Alert {
  id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  source: string;
  destination?: string;
  mitre_tactic?: string;
  chain_events?: string[];
  note?: string;
  triggered_at: string;
  updated_at: string;
}

export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'TOR' | 'CANARY' | null;

export interface TopologyNode {
  id: string;
  label?: string;
  type?: 'host' | 'router' | 'container' | 'vm' | 'unknown';
  x: number;
  y: number;
  threat?: ThreatLevel;
  cpu?: number;
  mem?: number;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
}

export interface OwasakaStats {
  events_total: number;
  events_by_type: Record<string, number>;
  connected_clients: number;
}

export interface EventRateSample {
  t: number;
  count: number;
  alerts: number;
}

export interface LogEntry {
  timestamp: number;
  message: string;
  type: 'info' | 'warn' | 'error' | 'system';
  eventType?: EventType;
}
