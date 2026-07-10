import type { Alert, OwasakaStats, TopologyNode, TopologyEdge } from '../types';

const HOST = (import.meta.env.VITE_API_HOST as string | undefined) ?? window.location.host;
const WS_PROTO = window.location.protocol === 'https:' ? 'wss' : 'ws';
const HTTP_PROTO = window.location.protocol;

export const API_BASE = `${HTTP_PROTO}//${HOST}`;
export const WS_URL   = `${WS_PROTO}://${HOST}/ws`;

function token(): string | null {
  return sessionStorage.getItem('oswaka_token');
}

function authHeaders(): HeadersInit {
  const t = token();
  return t ? { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' }
           : { 'Content-Type': 'application/json' };
}

export function buildWsUrl(): string {
  const t = token();
  return t ? `${WS_URL}?token=${t}` : WS_URL;
}

export async function fetchAlerts(status?: string, limit = 50): Promise<Alert[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (status) params.set('status', status);
  const res = await fetch(`${API_BASE}/api/alerts?${params}`, { headers: authHeaders() });
  if (!res.ok) return [];
  return res.json() as Promise<Alert[]>;
}

export async function patchAlert(
  id: string,
  status: string,
  note?: string,
): Promise<Alert | null> {
  const res = await fetch(`${API_BASE}/api/alerts/${id}`, {
    method: 'PATCH',
    headers: authHeaders(),
    body: JSON.stringify({ status, note }),
  });
  if (!res.ok) return null;
  return res.json() as Promise<Alert>;
}

export interface ContainmentResult {
  ip: string;
  nftables_cmd: string;
  logged: boolean;
}

export async function requestContainment(ip: string): Promise<ContainmentResult | null> {
  const res = await fetch(`${API_BASE}/api/incidents/containment`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ ip }),
  });
  if (!res.ok) return null;
  return res.json() as Promise<ContainmentResult>;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export async function fetchTopology(): Promise<TopologyData> {
  const res = await fetch(`${API_BASE}/api/topology`, { headers: authHeaders() });
  if (!res.ok) return { nodes: [], edges: [] };
  const raw = await res.json() as { nodes?: unknown[]; links?: unknown[] };
  const nodes = (raw.nodes ?? []) as TopologyNode[];
  const links = (raw.links ?? []) as TopologyEdge[];
  return {
    nodes: nodes.map((n, i) => ({
      ...n,
      x: (n as TopologyNode).x ?? 100 + (i % 5) * 220,
      y: (n as TopologyNode).y ?? 100 + Math.floor(i / 5) * 160,
    })),
    edges: links.map((l, i) => ({ ...l, id: `e${i}` })),
  };
}

export async function fetchStats(): Promise<OwasakaStats | null> {
  const res = await fetch(`${API_BASE}/api/stats`, { headers: authHeaders() });
  if (!res.ok) return null;
  return res.json() as Promise<OwasakaStats>;
}
