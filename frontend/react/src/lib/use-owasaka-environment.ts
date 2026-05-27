import { useEffect, useMemo, useState } from 'react';
import { getHealth, getReadiness, getSTH, getStats, getTopology, openEventSocket, owasakaConfig } from './api';
import type { ConsoleStat, HealthPayload, Incident, LiveEvent, ResponseAction, SensorSurface, STHPayload, TopologyGraph } from './types';

type EnvironmentState = {
  health: HealthPayload | null;
  readiness: HealthPayload | null;
  stats: Awaited<ReturnType<typeof getStats>>;
  topology: TopologyGraph | null;
  sth: STHPayload | null;
  events: LiveEvent[];
  wsConnected: boolean;
  lastError: string | null;
};

const initialState: EnvironmentState = {
  health: null,
  readiness: null,
  stats: null,
  topology: null,
  sth: null,
  events: [],
  wsConnected: false,
  lastError: null,
};

function healthStatus(payload: HealthPayload | null) {
  return payload?.status || payload?.overall || 'offline';
}

function surfaceStatus(ok: boolean, degraded = false): SensorSurface['status'] {
  if (!ok) return 'offline';
  return degraded ? 'degraded' : 'online';
}

export function useOwasakaEnvironment() {
  const [state, setState] = useState<EnvironmentState>(initialState);

  useEffect(() => {
    let mounted = true;
    const controller = new AbortController();

    async function refresh() {
      try {
        const [health, readiness, stats, topology, sth] = await Promise.all([
          getHealth(controller.signal),
          getReadiness(controller.signal),
          getStats(controller.signal),
          getTopology(controller.signal),
          getSTH(controller.signal),
        ]);
        if (!mounted) return;
        setState((current) => ({
          ...current,
          health,
          readiness,
          stats,
          topology: topology || current.topology,
          sth,
          lastError: null,
        }));
      } catch (error) {
        if (!mounted) return;
        setState((current) => ({
          ...current,
          health: null,
          lastError: error instanceof Error ? error.message : 'failed to reach OWASAKA core',
        }));
      }
    }

    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => {
      mounted = false;
      controller.abort();
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    let retry: number | undefined;
    let socket: WebSocket | null = null;
    let closed = false;

    const connect = () => {
      socket = openEventSocket(
        (event) => setState((current) => ({ ...current, events: [event, ...current.events].slice(0, 100) })),
        (topology) => setState((current) => ({ ...current, topology })),
        (wsConnected) => setState((current) => ({ ...current, wsConnected })),
      );
      socket.onclose = () => {
        setState((current) => ({ ...current, wsConnected: false }));
        if (!closed) retry = window.setTimeout(connect, 2500);
      };
    };

    connect();
    return () => {
      closed = true;
      if (retry) window.clearTimeout(retry);
      socket?.close();
    };
  }, []);

  const consoleStats: ConsoleStat[] = useMemo(() => {
    const topIpCount = state.stats?.top_ips_5m?.length ?? 0;
    return [
      { label: 'Buffered events', value: String(state.stats?.buffered_events ?? 0), hint: state.stats?.backpressure_policy || 'stream' },
      { label: 'Dropped events', value: String(state.stats?.dropped_events ?? 0), hint: 'backpressure' },
      { label: 'Topology nodes', value: String(state.topology?.nodes?.length ?? 0), hint: `${state.topology?.links?.length ?? 0} links` },
      { label: 'Tree size', value: String(state.sth?.tree_size ?? 0), hint: topIpCount ? `${topIpCount} top IPs` : 'Merkle' },
    ];
  }, [state.stats, state.sth, state.topology]);

  const sensorSurfaces: SensorSurface[] = useMemo(() => {
    const apiOnline = healthStatus(state.health) === 'online' || healthStatus(state.health) === 'healthy';
    const readyStatus = healthStatus(state.readiness);
    return [
      { name: 'Core API', coverage: apiOnline ? 100 : 0, status: surfaceStatus(apiOnline) },
      { name: 'Readiness', coverage: readyStatus === 'healthy' ? 100 : readyStatus === 'degraded' ? 72 : 0, status: surfaceStatus(Boolean(state.readiness), readyStatus === 'degraded') },
      { name: 'WebSocket', coverage: state.wsConnected ? 100 : 0, status: surfaceStatus(state.wsConnected) },
      { name: 'Topology', coverage: state.topology?.nodes?.length ? 92 : 0, status: surfaceStatus(Boolean(state.topology?.nodes?.length)) },
      { name: 'Transparency', coverage: state.sth ? 100 : 0, status: surfaceStatus(Boolean(state.sth)) },
    ];
  }, [state.health, state.readiness, state.sth, state.topology, state.wsConnected]);

  const responseActions: ResponseAction[] = useMemo(() => {
    const critical = state.events.filter((event) => event.severity === 'critical').length;
    const high = state.events.filter((event) => event.severity === 'high').length;
    return [
      { label: 'Triage', count: `${state.events.length} open`, tone: 'active' },
      { label: 'Containment', count: `${critical} queued`, tone: critical ? 'warning' : 'muted' },
      { label: 'Collection', count: `${state.sth?.tree_size ?? 0} leaves`, tone: 'calm' },
      { label: 'Recovery', count: `${high} pending`, tone: high ? 'warning' : 'muted' },
    ];
  }, [state.events, state.sth]);

  const incidents: Incident[] = useMemo(() => state.events
    .filter((event) => event.severity === 'critical' || event.severity === 'high')
    .map((event, index) => ({
      id: event.id || `INC-${index}`,
      title: event.summary,
      severity: event.severity === 'critical' ? 'critical' : 'high',
      status: event.severity === 'critical' ? 'containment' : 'triage',
      source: event.source,
      target: event.target,
      updatedAt: event.time,
    })), [state.events]);

  return {
    ...state,
    config: owasakaConfig,
    consoleStats,
    incidents,
    responseActions,
    sensorSurfaces,
    coreOnline: Boolean(state.health),
  };
}
