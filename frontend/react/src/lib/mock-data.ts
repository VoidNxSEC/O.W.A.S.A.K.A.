import {
  Activity,
  Database,
  Fingerprint,
  GitBranch,
  KeyRound,
  Layers3,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type {
  ConsoleStat,
  EvidenceStep,
  FingerprintRecord,
  Incident,
  LiveEvent,
  ResponseAction,
  SensorSurface,
  SystemLayer,
  TransparencyEntry,
} from './types';

export const systemLayers: SystemLayer[] = [
  { name: 'Presentation', detail: 'React · Svelte · TypeScript · WebSocket', icon: Terminal, accent: 'violet' },
  { name: 'Golang Core', detail: 'Network Intel · Discovery · Analytics', icon: Activity, accent: 'emerald' },
  { name: 'PKI Authority', detail: 'Root CA · JWT · Event · STH signers', icon: KeyRound, accent: 'amber' },
  { name: 'Encrypted Storage', detail: 'BoltDB · NAS · AES-256-GCM · Merkle', icon: Database, accent: 'blue' },
  { name: 'Transparency Log', detail: 'STH · Inclusion · Consistency', icon: GitBranch, accent: 'cyan' },
  { name: 'External Verifiers', detail: 'Spectre · Cerebro · Paper Journal', icon: ShieldCheck, accent: 'slate' },
];

export const fingerprints: FingerprintRecord[] = [
  { label: 'Root CA', value: '33:ba:47:f6:...', icon: ShieldCheck },
  { label: 'JWT signer', value: '716d:f935:...', icon: KeyRound },
  { label: 'Event signer', value: 'a1c4:23ee:...', icon: Fingerprint },
  { label: 'STH signer', value: 'd30f:8c73:...', icon: Layers3 },
];

export const evidenceFlow: EvidenceStep[] = [
  { label: 'Normalize event', description: 'Canonical envelope built from raw telemetry.' },
  { label: 'Sign canonical bytes', description: 'Event signer commits to exact evidence bytes.' },
  { label: 'Append Merkle leaf', description: 'Hash enters append-only transparency storage.' },
  { label: 'Publish STH', description: 'Signed tree head captures current root.' },
  { label: 'Verify externally', description: 'Independent verifier checks inclusion and consistency.' },
];

export const stats: ConsoleStat[] = [
  { label: 'Signed events', value: '42,118', hint: 'Ed25519' },
  { label: 'Tree size', value: '42k', hint: 'Merkle log' },
  { label: 'UI p95', value: '<100ms', hint: 'target' },
  { label: 'Trust domains', value: '3', hint: 'JWT · Event · STH' },
];

export const incidents: Incident[] = [
  {
    id: 'INC-0421',
    title: 'Anomalous east-west request burst',
    severity: 'critical',
    status: 'containment',
    source: 'edge-proxy-01',
    target: 'vault-bridge',
    updatedAt: '2m ago',
  },
  {
    id: 'INC-0418',
    title: 'Port scan against backup segment',
    severity: 'high',
    status: 'collection',
    source: 'lab-node-07',
    target: 'nas-backup-a',
    updatedAt: '17m ago',
  },
  {
    id: 'INC-0413',
    title: 'DNS tunneling heuristic match',
    severity: 'medium',
    status: 'triage',
    source: 'resolver-a',
    target: 'updates.local',
    updatedAt: '41m ago',
  },
];

export const transparencyEntries: TransparencyEntry[] = [
  {
    id: 'STH-42118',
    treeSize: 42118,
    rootHash: 'b1fc8c2d7a4e0a6d3f14c9ab0f83d77e',
    signedAt: '2026-05-27 18:20 UTC',
    verifier: 'Spectre',
    status: 'verified',
  },
  {
    id: 'STH-42102',
    treeSize: 42102,
    rootHash: '8a02d45b77c11bd9ee03271f4af0e635',
    signedAt: '2026-05-27 18:05 UTC',
    verifier: 'Cerebro',
    status: 'verified',
  },
  {
    id: 'STH-42081',
    treeSize: 42081,
    rootHash: 'd98eec7347120a22e48160753c0bd24a',
    signedAt: '2026-05-27 17:40 UTC',
    verifier: 'Paper Journal',
    status: 'pending',
  },
];

export const liveEvents: LiveEvent[] = [
  {
    id: 'EVT-8182',
    type: 'THREAT_ALERT',
    source: 'edge-proxy-01',
    target: 'vault-bridge',
    severity: 'critical',
    time: '18:48:09',
    summary: 'Anomalous east-west request burst crossed containment threshold.',
  },
  {
    id: 'EVT-8177',
    type: 'PORT_SCAN',
    source: 'lab-node-07',
    target: 'nas-backup-a',
    severity: 'high',
    time: '18:46:31',
    summary: 'SYN sequence touched backup segment control ports.',
  },
  {
    id: 'EVT-8164',
    type: 'DNS',
    source: 'resolver-a',
    target: 'updates.local',
    severity: 'medium',
    time: '18:42:18',
    summary: 'High entropy label observed below allowed internal zone.',
  },
  {
    id: 'EVT-8122',
    type: 'ARP',
    source: 'switch-core',
    target: 'operator-lan',
    severity: 'info',
    time: '18:37:44',
    summary: 'ARP baseline refreshed, no duplicate gateway claim.',
  },
];

export const sensorSurfaces: SensorSurface[] = [
  { name: 'DNS resolver', coverage: 98, status: 'online' },
  { name: 'Proxy DPI', coverage: 91, status: 'online' },
  { name: 'ARP watch', coverage: 86, status: 'online' },
  { name: 'VM inventory', coverage: 74, status: 'degraded' },
  { name: 'Backup chain', coverage: 100, status: 'online' },
];

export const responseActions: ResponseAction[] = [
  { label: 'Triage', count: '04 open', tone: 'active' },
  { label: 'Containment', count: '02 queued', tone: 'warning' },
  { label: 'Collection', count: '18 artifacts', tone: 'calm' },
  { label: 'Recovery', count: '01 pending', tone: 'muted' },
];
