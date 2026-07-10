import React, { useMemo } from 'react';
import type { NetworkEvent, Alert, EventRateSample, Severity } from '../types';
import { cn } from '../lib/utils';
import { Activity, Shield, Link2, AlertTriangle } from 'lucide-react';
import { LineChart, Line, ResponsiveContainer, Tooltip } from 'recharts';

interface Props {
  events: NetworkEvent[];
  rateSamples: EventRateSample[];
  alerts: Alert[];
}

const SEV_STYLES: Record<Severity, string> = {
  CRITICAL: 'text-red-400    bg-red-500/10    border-red-500/20',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  MEDIUM:   'text-amber-400  bg-amber-500/10  border-amber-500/20',
  LOW:      'text-blue-400   bg-blue-500/10   border-blue-500/20',
};

export function SystemInsights({ events, rateSamples, alerts }: Props) {
  const alertsByStatus = useMemo(() => {
    const m: Record<string, number> = { NEW: 0, TRIAGING: 0, CONTAINED: 0, CLOSED: 0 };
    for (const a of alerts) m[a.status] = (m[a.status] ?? 0) + 1;
    return m;
  }, [alerts]);

  const eventsByType = useMemo(() => {
    const m: Record<string, number> = {};
    for (const ev of events) m[ev.type] = (m[ev.type] ?? 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [events]);

  const killChains = useMemo(() =>
    events.filter(e => e.metadata?.mitre_tactic),
  [events]);

  const uniqueChainSources = useMemo(() => {
    const s = new Set<string>();
    killChains.forEach(e => s.add(e.source));
    return s.size;
  }, [killChains]);

  const latestAlerts = alerts.filter(a => a.status === 'NEW').slice(0, 4);

  const totalRate = rateSamples.reduce((s, r) => s + r.count, 0);
  const avgRate   = rateSamples.length > 0 ? (totalRate / rateSamples.length).toFixed(1) : '0';

  return (
    <div className="flex flex-col h-full bg-[#111111] border-l border-white/10 text-white w-72 shrink-0 overflow-y-auto scrollbar-hide">
      <div className="p-4 border-b border-white/10 flex items-center gap-2 shrink-0">
        <Activity className="w-4 h-4 text-indigo-400" />
        <h2 className="font-semibold text-xs uppercase tracking-tight opacity-80">SIEM Insights</h2>
      </div>

      <div className="p-4 space-y-5 flex-1">
        {/* ── Event rate ── */}
        <section className="space-y-2">
          <SectionTitle icon={Activity} label="Event Rate" />
          <div className="bg-white/5 border border-white/10 rounded-lg p-3">
            <div className="flex justify-between items-baseline mb-2">
              <span className="text-2xl font-bold font-mono">{avgRate}</span>
              <span className="text-[10px] text-white/30">events/sec</span>
            </div>
            <div className="h-16">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rateSamples}>
                  <Line type="monotone" dataKey="count"  stroke="#818cf8" strokeWidth={2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="alerts" stroke="#ef4444" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#000', border: '1px solid rgba(255,255,255,0.1)', fontSize: 10 }}
                    labelFormatter={() => ''}
                    formatter={(val, name) => [val ?? 0, name === 'count' ? 'events' : 'alerts']}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-between text-[10px] font-mono mt-1">
              <span className="text-indigo-400">events</span>
              <span className="text-red-400">alerts</span>
            </div>
          </div>
        </section>

        {/* ── Alert lifecycle ── */}
        <section className="space-y-2">
          <SectionTitle icon={Shield} label="Alert Lifecycle" />
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'NEW',       count: alertsByStatus.NEW ?? 0,       cls: 'text-red-400 border-red-500/20 bg-red-500/5' },
              { label: 'TRIAGING',  count: alertsByStatus.TRIAGING ?? 0,  cls: 'text-amber-400 border-amber-500/20 bg-amber-500/5' },
              { label: 'CONTAINED', count: alertsByStatus.CONTAINED ?? 0, cls: 'text-blue-400 border-blue-500/20 bg-blue-500/5' },
              { label: 'CLOSED',    count: alertsByStatus.CLOSED ?? 0,    cls: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5' },
            ].map(s => (
              <div key={s.label} className={cn('rounded-lg border p-2.5', s.cls)}>
                <div className="text-lg font-bold font-mono">{s.count}</div>
                <div className="text-[9px] uppercase tracking-wider opacity-60">{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Kill chains ── */}
        <section className="space-y-2">
          <SectionTitle icon={Link2} label="Kill Chains" />
          {killChains.length === 0 ? (
            <div className="bg-white/5 border border-white/10 rounded-lg p-3 text-xs text-white/30">
              No active kill chains detected.
            </div>
          ) : (
            <div className="space-y-1.5">
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-white/40">Chain events</span>
                <span className="text-indigo-400">{killChains.length}</span>
              </div>
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-white/40">Unique sources</span>
                <span className="text-orange-400">{uniqueChainSources}</span>
              </div>
              <div className="mt-2 space-y-1">
                {killChains.slice(0, 3).map(ev => (
                  <div key={ev.id} className="flex items-center gap-2 text-[10px] font-mono bg-indigo-500/5 border border-indigo-500/15 rounded px-2 py-1">
                    <span className="text-indigo-300 shrink-0">{ev.metadata.mitre_tactic as string}</span>
                    <span className="text-white/40 truncate">{ev.source}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* ── Top event types ── */}
        <section className="space-y-2">
          <SectionTitle icon={Activity} label="Event Distribution" />
          <div className="space-y-1.5">
            {eventsByType.map(([type, count]) => {
              const pct = events.length > 0 ? (count / events.length) * 100 : 0;
              return (
                <div key={type} className="space-y-0.5">
                  <div className="flex justify-between text-[9px] font-mono">
                    <span className="text-white/40">{type}</span>
                    <span className="text-white/50">{count}</span>
                  </div>
                  <div className="w-full bg-black/40 h-0.5 rounded-full overflow-hidden">
                    <div
                      className={cn('h-full rounded-full transition-all duration-500', EVENT_BAR_COLOR[type] ?? 'bg-white/20')}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* ── Latest alerts ── */}
        {latestAlerts.length > 0 && (
          <section className="space-y-2">
            <SectionTitle icon={AlertTriangle} label="Latest Alerts" />
            <div className="space-y-1.5">
              {latestAlerts.map(a => (
                <div
                  key={a.id}
                  className={cn('rounded-lg border px-2.5 py-2 text-[10px]', SEV_STYLES[a.severity])}
                >
                  <div className="font-bold truncate">{a.rule_name}</div>
                  <div className="font-mono opacity-60 truncate mt-0.5">{a.source}</div>
                  {a.mitre_tactic && (
                    <span className="inline-block mt-1 text-[9px] bg-black/30 px-1 rounded">{a.mitre_tactic}</span>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

const EVENT_BAR_COLOR: Record<string, string> = {
  DNS:          'bg-cyan-500',
  ARP:          'bg-emerald-500',
  PORT_SCAN:    'bg-orange-500',
  THREAT_ALERT: 'bg-red-500',
  PROXY:        'bg-blue-500',
  VM:           'bg-indigo-500',
  TOR:          'bg-purple-500',
  CANARY:       'bg-amber-500',
  PHYSICAL:     'bg-slate-400',
};

function SectionTitle({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <h3 className="text-[9px] font-bold text-white/30 uppercase tracking-[0.18em] flex items-center gap-1.5">
      <Icon className="w-3 h-3" /> {label}
    </h3>
  );
}
