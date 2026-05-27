import type { HealthPayload, LiveEvent, ProcessorStats, STHPayload, TopologyGraph } from './types';

const defaultApiURL = 'http://127.0.0.1:8080';

export const owasakaConfig = {
  apiURL: (import.meta.env.VITE_OWASAKA_API_URL || defaultApiURL).replace(/\/$/, ''),
  wsURL: import.meta.env.VITE_OWASAKA_WS_URL || 'ws://127.0.0.1:8080/ws',
  token: import.meta.env.VITE_OWASAKA_TOKEN || '',
};

type FetchOptions = {
  signal?: AbortSignal;
  optional?: boolean;
};

async function fetchJSON<T>(path: string, options: FetchOptions = {}): Promise<T | null> {
  const headers: HeadersInit = {};
  if (owasakaConfig.token) {
    headers.Authorization = `Bearer ${owasakaConfig.token}`;
  }

  const response = await fetch(`${owasakaConfig.apiURL}${path}`, {
    headers,
    signal: options.signal,
  });

  if (!response.ok) {
    if (options.optional && (response.status === 401 || response.status === 403 || response.status === 404 || response.status === 503)) {
      return null;
    }
    throw new Error(`${path} returned ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export function getHealth(signal?: AbortSignal) {
  return fetchJSON<HealthPayload>('/health', { signal });
}

export function getReadiness(signal?: AbortSignal) {
  return fetchJSON<HealthPayload>('/readyz', { signal, optional: true });
}

export function getStats(signal?: AbortSignal) {
  return fetchJSON<ProcessorStats>('/api/stats', { signal, optional: true });
}

export function getTopology(signal?: AbortSignal) {
  return fetchJSON<TopologyGraph>('/api/topology', { signal, optional: true });
}

export function getSTH(signal?: AbortSignal) {
  return fetchJSON<STHPayload>('/api/transparency/sth', { signal, optional: true });
}

export function normalizeEvent(payload: any): LiveEvent | null {
  const event = payload?.type === 'TOPOLOGY_UPDATE' ? null : payload;
  if (!event) return null;

  const type = String(event.type || 'SYSTEM');
  const metadata = event.metadata || {};
  const timestamp = event.timestamp ? new Date(event.timestamp) : new Date();
  const severity = type === 'THREAT_ALERT'
    ? 'critical'
    : type === 'PORT_SCAN'
      ? 'high'
      : type === 'DNS'
        ? 'medium'
        : type === 'ARP'
          ? 'info'
          : 'low';

  return {
    id: String(event.id || `${type}-${timestamp.getTime()}`),
    type,
    source: String(event.source || metadata.source || 'unknown'),
    target: String(event.destination || metadata.target || 'unknown'),
    severity,
    time: timestamp.toLocaleTimeString(),
    summary: String(metadata.reason || metadata.summary || metadata.query || `${type} event received from core`),
    raw: payload,
  };
}

export function openEventSocket(onEvent: (event: LiveEvent) => void, onTopology?: (graph: TopologyGraph) => void, onState?: (connected: boolean) => void) {
  const socket = new WebSocket(owasakaConfig.wsURL);

  socket.onopen = () => onState?.(true);
  socket.onclose = () => onState?.(false);
  socket.onerror = () => onState?.(false);
  socket.onmessage = (message) => {
    const payload = JSON.parse(message.data);
    if (payload?.type === 'TOPOLOGY_UPDATE' && payload.data) {
      onTopology?.(payload.data as TopologyGraph);
      return;
    }
    const event = normalizeEvent(payload);
    if (event) onEvent(event);
  };

  return socket;
}
