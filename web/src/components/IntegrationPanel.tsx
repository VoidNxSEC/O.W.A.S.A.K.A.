import React from 'react';
import type { NetworkEvent, EventType } from '../types';
import { cn } from '../lib/utils';
import {
  Globe, Radio, Shield, Monitor, Usb, Ghost, Activity,
  AlertTriangle, Minus,
} from 'lucide-react';

const SURFACES: Array<{ type: EventType; label: string; icon: React.ElementType; endpoint: string }> = [
  { type: 'DNS',       label: 'DNS Monitor',    icon: Globe,    endpoint: ':53 resolver' },
  { type: 'ARP',       label: 'ARP Watcher',    icon: Radio,    endpoint: 'L2 broadcast' },
  { type: 'PROXY',     label: 'Proxy DPI',      icon: Shield,   endpoint: ':8888 MITM' },
  { type: 'VM',        label: 'VM Scanner',     icon: Monitor,  endpoint: 'docker+libvirt' },
  { type: 'PHYSICAL',  label: 'USB / Physical', icon: Usb,      endpoint: 'sysfs poll' },
  { type: 'TOR',       label: 'Tor Detection',  icon: Ghost,    endpoint: 'exit node list' },
  { type: 'CANARY',    label: 'Canary Tokens',  icon: AlertTriangle, endpoint: 'webhook ingress' },
];

const IDLE_MS   = 5  * 60 * 1000;
const OFFLINE_MS = 30 * 60 * 1000;

function surfaceStatus(type: EventType, lastSeen: Map<EventType, number>) {
  const ts = lastSeen.get(type);
  if (!ts) return 'offline' as const;
  const age = Date.now() - ts;
  if (age < IDLE_MS)    return 'active' as const;
  if (age < OFFLINE_MS) return 'idle'   as const;
  return 'offline' as const;
}

function countByType(events: NetworkEvent[], type: EventType): number {
  return events.filter(e => e.type === type).length;
}

interface Props {
  events: NetworkEvent[];
  lastSeen: Map<EventType, number>;
  surfaceTypes: EventType[];
}

export function IntegrationPanel({ events, lastSeen }: Props) {
  const threats    = events.filter(e => e.type === 'THREAT_ALERT').length;
  const chains     = events.filter(e => e.metadata?.mitre_tactic).length;
  const activeCount = SURFACES.filter(s => surfaceStatus(s.type, lastSeen) === 'active').length;

  const healthPct = SURFACES.length > 0 ? (activeCount / SURFACES.length) * 100 : 0;

  return (
    <div className="flex flex-col h-full bg-[#0A0A0A] border-r border-white/10 text-white w-64 shrink-0">
      <div className="p-4 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-emerald-400" />
          <h2 className="font-semibold text-xs tracking-tight uppercase opacity-80">Surfaces</h2>
        </div>
        <span className={cn(
          'text-[10px] px-1.5 py-0.5 rounded border font-bold',
          activeCount > 0
            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
            : 'bg-white/5 text-white/30 border-white/10',
        )}>
          {activeCount}/{SURFACES.length} ACTIVE
        </span>
      </div>

      <div className="p-3 space-y-1.5 overflow-y-auto flex-1 scrollbar-hide">
        <div className="text-[9px] font-bold text-white/25 uppercase tracking-[0.2em] mb-2 px-1">
          Watched Attack Surfaces
        </div>

        {SURFACES.map(s => {
          const status = surfaceStatus(s.type, lastSeen);
          const count  = countByType(events, s.type);
          const Icon   = s.icon;

          return (
            <div
              key={s.type}
              className="group bg-white/[0.02] border border-white/5 rounded-lg p-2.5 hover:bg-white/[0.05] hover:border-white/10 transition-all"
            >
              <div className="flex items-center gap-2.5">
                <div className={cn('p-1.5 rounded-md shrink-0 transition-colors', {
                  'bg-emerald-500/10 text-emerald-400': status === 'active',
                  'bg-amber-500/10   text-amber-400':   status === 'idle',
                  'bg-white/5        text-white/20':    status === 'offline',
                })}>
                  <Icon className="w-3 h-3" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-white/80 truncate">{s.label}</span>
                    <StatusDot status={status} />
                  </div>
                  <div className="flex justify-between text-[9px] font-mono text-white/25 mt-0.5">
                    <span className="truncate">{s.endpoint}</span>
                    {count > 0 && <span className="ml-1 shrink-0 text-white/40">{count}</span>}
                  </div>
                </div>
              </div>
            </div>
          );
        })}

        {/* ── Kill chain summary ── */}
        <div className="pt-3 mt-3 border-t border-white/5">
          <div className="text-[9px] font-bold text-white/25 uppercase tracking-[0.2em] mb-2 px-1">
            Kill Chains
          </div>
          <KillChainBadges events={events} />
        </div>

        {/* ── Ecosystem health ── */}
        <div className="pt-3 border-t border-white/5">
          <div className="text-[9px] font-bold text-white/25 uppercase tracking-[0.2em] mb-3 px-1">
            Pipeline Health
          </div>
          <HealthBar label="Surface coverage" value={healthPct} />
          <HealthBar
            label="Alert closure rate"
            value={threats > 0 ? Math.min(100, (events.filter(e => e.type !== 'THREAT_ALERT').length / Math.max(1, threats)) * 10) : 100}
          />
          <HealthBar label="Chain detection" value={Math.min(100, chains * 20)} color="purple" />
        </div>
      </div>

      <div className="p-3 border-t border-white/10 bg-white/[0.02]">
        <div className="flex justify-between text-[9px] font-mono text-white/25">
          <span>{threats} threats</span>
          <span>{chains} chains</span>
          <span>{events.length} events</span>
        </div>
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: 'active' | 'idle' | 'offline' }) {
  return (
    <div className={cn('w-1.5 h-1.5 rounded-full shrink-0', {
      'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.5)] animate-pulse': status === 'active',
      'bg-amber-400':  status === 'idle',
      'bg-white/10':   status === 'offline',
    })} />
  );
}

function HealthBar({
  label, value, color = 'emerald',
}: { label: string; value: number; color?: 'emerald' | 'amber' | 'purple' }) {
  const barClass = {
    emerald: 'bg-emerald-500',
    amber:   'bg-amber-500',
    purple:  'bg-purple-500',
  }[color];
  const textClass = {
    emerald: value < 60 ? 'text-amber-400' : 'text-emerald-400',
    amber:   'text-amber-400',
    purple:  'text-purple-400',
  }[color];
  return (
    <div className="space-y-1 mb-2">
      <div className="flex justify-between text-[9px] font-mono">
        <span className="text-white/30">{label}</span>
        <span className={textClass}>{value.toFixed(0)}%</span>
      </div>
      <div className="w-full bg-white/5 h-0.5 rounded-full overflow-hidden">
        <div className={cn('h-full transition-all duration-1000', barClass)} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

const TACTIC_COLORS: Record<string, string> = {
  TA0043: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
  TA0001: 'bg-red-500/20    text-red-300    border-red-500/30',
  TA0002: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  TA0003: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
};

function KillChainBadges({ events }: { events: NetworkEvent[] }) {
  const tactic_counts = new Map<string, number>();
  for (const ev of events) {
    const t = ev.metadata?.mitre_tactic as string | undefined;
    if (t) tactic_counts.set(t, (tactic_counts.get(t) ?? 0) + 1);
  }
  if (tactic_counts.size === 0) {
    return (
      <div className="flex items-center gap-1.5 text-white/15 px-1">
        <Minus className="w-3 h-3" />
        <span className="text-[9px] font-mono">no active chains</span>
      </div>
    );
  }
  return (
    <div className="flex flex-wrap gap-1 px-1">
      {Array.from(tactic_counts.entries()).map(([t, n]) => (
        <span
          key={t}
          className={cn('text-[9px] font-mono px-1.5 py-0.5 rounded border', TACTIC_COLORS[t] ?? 'bg-white/5 text-white/40 border-white/10')}
        >
          {t} ×{n}
        </span>
      ))}
    </div>
  );
}
