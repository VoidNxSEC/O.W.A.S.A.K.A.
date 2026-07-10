import React, { useEffect, useState, useRef, useCallback } from 'react';
import { ShieldAlert } from 'lucide-react';
import type {
  NetworkEvent, Alert, TopologyNode, TopologyEdge,
  LogEntry, EventRateSample, ThreatLevel, EventType,
} from './types';
import {
  buildWsUrl, fetchAlerts, fetchTopology, fetchStats, patchAlert, requestContainment,
} from './lib/owasaka';
import { SpatialCanvas }     from './components/SpatialCanvas';
import { SystemInsights }    from './components/SystemInsights';
import { IntegrationPanel }  from './components/IntegrationPanel';
import { SystemTerminal }    from './components/SystemTerminal';
import { AlertPanel }        from './components/AlertPanel';

const MAX_EVENTS  = 500;
const MAX_LOGS    = 100;
const MAX_SAMPLES = 30;
const SURFACE_TYPES: EventType[] = ['DNS','ARP','PROXY','VM','PHYSICAL','TOR','CANARY'];

function buildThreatMap(events: NetworkEvent[]): Map<string, ThreatLevel> {
  const map = new Map<string, ThreatLevel>();
  const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, TOR: 2, CANARY: 1 };
  for (const ev of events) {
    const ip = ev.source;
    if (!ip) continue;
    let level: ThreatLevel = null;
    if (ev.type === 'TOR')    level = 'TOR';
    if (ev.type === 'CANARY') level = 'CANARY';
    if (ev.type === 'THREAT_ALERT') {
      const sev = (ev.metadata?.severity as string | undefined)?.toUpperCase();
      level = (sev === 'CRITICAL' ? 'CRITICAL' : 'HIGH') as ThreatLevel;
    }
    if (!level) continue;
    const cur = map.get(ip);
    if (!cur || rank[level] > rank[cur]) map.set(ip, level);
  }
  return map;
}

export default function App() {
  const [isConnected, setIsConnected]   = useState(false);
  const [events, setEvents]             = useState<NetworkEvent[]>([]);
  const [logs, setLogs]                 = useState<LogEntry[]>([]);
  const [alerts, setAlerts]             = useState<Alert[]>([]);
  const [topoNodes, setTopoNodes]       = useState<TopologyNode[]>([]);
  const [topoEdges, setTopoEdges]       = useState<TopologyEdge[]>([]);
  const [rateSamples, setRateSamples]   = useState<EventRateSample[]>([]);
  const [activeTab, setActiveTab]       = useState<'feed' | 'alerts'>('feed');
  const [lastSeen, setLastSeen]         = useState<Map<EventType, number>>(new Map());
  const [containResult, setContainResult] = useState<{ ip: string; cmd: string } | null>(null);

  const wsRef     = useRef<WebSocket | null>(null);
  const countRef  = useRef(0);
  const alertsRef = useRef(0);

  const addLog = useCallback((message: string, type: LogEntry['type'], eventType?: EventType) => {
    setLogs(prev => {
      const next = [...prev, { timestamp: Date.now(), message, type, eventType }];
      return next.length > MAX_LOGS ? next.slice(-MAX_LOGS) : next;
    });
  }, []);

  // ── WebSocket ────────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(buildWsUrl());
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      addLog('OWASAKA core connected — pipeline live', 'system');
      // refresh topology + alerts on reconnect
      fetchTopology().then(({ nodes, edges }) => {
        setTopoNodes(nodes);
        setTopoEdges(edges);
      });
      fetchAlerts(undefined, 100).then(setAlerts);
    };

    ws.onclose = () => {
      setIsConnected(false);
      addLog('Core connection lost — reconnecting in 3s', 'error');
      setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();

    ws.onmessage = (msg) => {
      let data: unknown;
      try { data = JSON.parse(msg.data as string); } catch { return; }

      const d = data as Record<string, unknown>;

      // System messages (ALERT_UPDATE, TOPOLOGY_UPDATE, CONTAINMENT_REQUEST)
      if (d.event) {
        if (d.event === 'ALERT_UPDATE') {
          const updated = d.payload as Alert;
          setAlerts(prev => prev.map(a => a.id === updated.id ? updated : a));
        }
        if (d.event === 'TOPOLOGY_UPDATE') {
          fetchTopology().then(({ nodes, edges }) => {
            setTopoNodes(nodes);
            setTopoEdges(edges);
          });
        }
        return;
      }

      // NetworkEvent
      if (!d.type || !d.id) return;
      const ev = d as unknown as NetworkEvent;

      setEvents(prev => {
        const next = [ev, ...prev];
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
      });

      setLastSeen(prev => new Map(prev).set(ev.type as EventType, Date.now()));

      countRef.current++;
      if (ev.type === 'THREAT_ALERT') {
        alertsRef.current++;
        fetchAlerts(undefined, 100).then(setAlerts);
        setActiveTab('alerts');
      }

      const sev = (ev.metadata?.severity as string | undefined) ?? '';
      const logType: LogEntry['type'] =
        ev.type === 'THREAT_ALERT' ? (sev === 'CRITICAL' ? 'error' : 'warn') :
        ev.type === 'TOR' || ev.type === 'CANARY' ? 'warn' : 'info';

      const dest = ev.destination ? ` → ${ev.destination}` : '';
      const detail = ev.metadata?.rule_name
        ? ` [${ev.metadata.rule_name as string}]`
        : ev.metadata?.domain ? ` (${ev.metadata.domain as string})` : '';
      addLog(`${ev.type}  ${ev.source}${dest}${detail}`, logType, ev.type);
    };
  }, [addLog]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  // ── Rate sampling (1/sec) ────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setRateSamples(prev => {
        const next = [
          ...prev,
          { t: Date.now(), count: countRef.current, alerts: alertsRef.current },
        ];
        countRef.current  = 0;
        alertsRef.current = 0;
        return next.length > MAX_SAMPLES ? next.slice(-MAX_SAMPLES) : next;
      });
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // ── Initial data load ────────────────────────────────────────────────────
  useEffect(() => {
    fetchTopology().then(({ nodes, edges }) => {
      setTopoNodes(nodes);
      setTopoEdges(edges);
    });
    fetchAlerts(undefined, 100).then(setAlerts);
    const statsInterval = setInterval(() => {
      fetchStats().catch(() => null);
    }, 10000);
    return () => clearInterval(statsInterval);
  }, []);

  // ── Alert actions ────────────────────────────────────────────────────────
  const handleTriage = useCallback(async (id: string) => {
    const updated = await patchAlert(id, 'TRIAGING', 'triaged via web UI');
    if (updated) setAlerts(prev => prev.map(a => a.id === id ? updated : a));
  }, []);

  const handleClose = useCallback(async (id: string) => {
    const updated = await patchAlert(id, 'CLOSED', 'closed via web UI');
    if (updated) setAlerts(prev => prev.map(a => a.id === id ? updated : a));
  }, []);

  const handleSeal = useCallback(async (ip: string) => {
    const result = await requestContainment(ip);
    const cmd = result?.nftables_cmd ?? `nft add rule inet filter input ip saddr ${ip} drop`;
    setContainResult({ ip, cmd });
    navigator.clipboard?.writeText(cmd).catch(() => null);
  }, []);

  // ── Node drag ────────────────────────────────────────────────────────────
  const handleNodeMove = useCallback((id: string, x: number, y: number) => {
    setTopoNodes(prev => prev.map(n => n.id === id ? { ...n, x, y } : n));
  }, []);

  const threatMap = buildThreatMap(events.slice(0, 200));
  const newAlertCount = alerts.filter(a => a.status === 'NEW').length;

  return (
    <div className="flex flex-col h-screen bg-black text-white font-sans overflow-hidden">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="h-14 border-b border-white/10 bg-[#0A0A0A] flex items-center justify-between px-4 shrink-0 z-10">
        <div className="flex items-center gap-3">
          <div className="bg-red-600/80 p-1.5 rounded-md">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <h1 className="font-semibold text-lg tracking-tight">
            O.W.A.S.A.K.A.{' '}
            <span className="text-[10px] opacity-40 uppercase ml-2 tracking-widest">
              Zero-Trust SIEM
            </span>
          </h1>
          <div className="ml-4 px-2 py-1 rounded-full bg-white/5 border border-white/10 flex items-center gap-2 text-xs">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
            <span className="text-white/60 font-mono">
              {isConnected ? 'Pipeline Live' : 'Core Offline'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono text-white/40">
          <span>{events.length} events</span>
          <span className="text-white/20">|</span>
          <span className={newAlertCount > 0 ? 'text-red-400' : ''}>{newAlertCount} new alerts</span>
          <span className="text-white/20">|</span>
          <span>{topoNodes.length} nodes</span>
        </div>
      </header>

      {/* ── Main ──────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">
        <IntegrationPanel events={events} lastSeen={lastSeen} surfaceTypes={SURFACE_TYPES} />

        <div className="flex-1 flex flex-col min-w-0">
          <main className="flex-1 relative">
            <SpatialCanvas
              nodes={topoNodes}
              edges={topoEdges}
              threatMap={threatMap}
              onNodeMove={handleNodeMove}
              onSealHost={handleSeal}
            />
          </main>

          {/* ── Bottom tabs ─────────────────────────────────────────── */}
          <div className="h-52 border-t border-white/10 flex flex-col">
            <div className="h-8 bg-white/5 border-b border-white/10 flex items-center shrink-0">
              {(['feed', 'alerts'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 h-full text-[10px] font-bold uppercase tracking-widest transition-colors flex items-center gap-2 ${
                    activeTab === tab
                      ? 'text-white border-b-2 border-red-500 bg-white/5'
                      : 'text-white/30 hover:text-white/60'
                  }`}
                >
                  {tab === 'feed' ? 'Event Feed' : (
                    <>
                      Alerts
                      {newAlertCount > 0 && (
                        <span className="bg-red-600 text-white px-1.5 py-0.5 rounded text-[9px]">
                          {newAlertCount}
                        </span>
                      )}
                    </>
                  )}
                </button>
              ))}
            </div>
            <div className="flex-1 overflow-hidden">
              {activeTab === 'feed' ? (
                <SystemTerminal logs={logs} />
              ) : (
                <AlertPanel
                  alerts={alerts}
                  onTriage={handleTriage}
                  onClose={handleClose}
                  onSeal={handleSeal}
                />
              )}
            </div>
          </div>
        </div>

        <SystemInsights events={events} rateSamples={rateSamples} alerts={alerts} />
      </div>

      {/* ── Containment modal ─────────────────────────────────────────── */}
      {containResult && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center"
          onClick={() => setContainResult(null)}
        >
          <div
            className="bg-[#0d1117] border border-red-500/40 rounded-xl p-6 w-[540px] max-w-full shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <h3 className="text-red-400 font-bold uppercase tracking-widest text-sm mb-4">
              Containment — {containResult.ip}
            </h3>
            <p className="text-white/50 text-xs mb-3">
              nftables command (copied to clipboard):
            </p>
            <pre className="bg-black/60 border border-white/10 rounded-lg p-3 text-xs font-mono text-red-300 mb-4 select-all">
              {containResult.cmd}
            </pre>
            <p className="text-white/30 text-[10px] mb-4">
              Run as root to take immediate effect. Containment request logged in SIEM.
            </p>
            <button
              onClick={() => setContainResult(null)}
              className="w-full py-2 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 rounded-lg text-xs font-bold uppercase tracking-widest text-red-400 transition-all"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
