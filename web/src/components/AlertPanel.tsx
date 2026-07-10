import React, { useState } from 'react';
import type { Alert, AlertStatus, Severity } from '../types';
import { cn } from '../lib/utils';
import { ShieldOff, AlertTriangle, CheckCircle2, RefreshCw, Filter } from 'lucide-react';

const SEV_CHIP: Record<Severity, string> = {
  CRITICAL: 'bg-red-600    text-white',
  HIGH:     'bg-orange-600 text-white',
  MEDIUM:   'bg-amber-600  text-black',
  LOW:      'bg-blue-700   text-white',
};

const STATUS_CHIP: Record<AlertStatus, string> = {
  NEW:       'bg-red-500/15    text-red-300    border-red-500/25',
  TRIAGING:  'bg-amber-500/15  text-amber-300  border-amber-500/25',
  CONTAINED: 'bg-blue-500/15   text-blue-300   border-blue-500/25',
  CLOSED:    'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
};

interface Props {
  alerts: Alert[];
  onTriage: (id: string) => void;
  onClose:  (id: string) => void;
  onSeal:   (ip: string) => void;
}

const ALL_STATUSES: AlertStatus[] = ['NEW', 'TRIAGING', 'CONTAINED', 'CLOSED'];

export function AlertPanel({ alerts, onTriage, onClose, onSeal }: Props) {
  const [filter, setFilter] = useState<AlertStatus | 'ALL'>('NEW');

  const visible = filter === 'ALL'
    ? alerts
    : alerts.filter(a => a.status === filter);

  const countFor = (s: AlertStatus | 'ALL') =>
    s === 'ALL' ? alerts.length : alerts.filter(a => a.status === s).length;

  return (
    <div className="h-full flex flex-col bg-[#050505] font-mono text-xs">
      {/* Filter bar */}
      <div className="flex items-center gap-1 px-3 py-1.5 border-b border-white/5 shrink-0">
        <Filter className="w-3 h-3 text-white/20 mr-1" />
        {(['ALL', ...ALL_STATUSES] as const).map(s => {
          const n = countFor(s);
          return (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={cn(
                'px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide transition-all',
                filter === s
                  ? 'bg-red-600/20 text-red-400 border border-red-500/30'
                  : 'text-white/25 hover:text-white/50',
              )}
            >
              {s} {n > 0 && <span className="opacity-70">({n})</span>}
            </button>
          );
        })}
      </div>

      {/* Alert list */}
      <div className="flex-1 overflow-y-auto scrollbar-hide">
        {visible.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/30 mx-auto mb-2" />
              <p className="text-white/20 text-[10px]">No {filter === 'ALL' ? '' : filter.toLowerCase()} alerts</p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {visible.map(alert => (
              <AlertRow
                key={alert.id}
                alert={alert}
                onTriage={onTriage}
                onClose={onClose}
                onSeal={onSeal}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AlertRow({
  alert, onTriage, onClose, onSeal,
}: { alert: Alert; onTriage: (id: string) => void; onClose: (id: string) => void; onSeal: (ip: string) => void }) {
  const ts = new Date(alert.triggered_at).toLocaleTimeString('en', { hour12: false });

  return (
    <div className={cn(
      'flex items-center gap-3 px-3 py-2 hover:bg-white/[0.03] transition-colors',
      alert.severity === 'CRITICAL' ? 'border-l-2 border-red-500' :
      alert.severity === 'HIGH'     ? 'border-l-2 border-orange-500' :
      'border-l-2 border-transparent',
    )}>
      {/* Severity chip */}
      <span className={cn('shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded uppercase', SEV_CHIP[alert.severity])}>
        {alert.severity}
      </span>

      {/* Main info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-white/70 font-bold truncate">{alert.rule_name}</span>
          {alert.mitre_tactic && (
            <span className="shrink-0 text-[9px] bg-indigo-500/15 text-indigo-300 border border-indigo-500/20 px-1 rounded">
              {alert.mitre_tactic}
            </span>
          )}
        </div>
        <div className="text-white/30 truncate mt-0.5">
          {alert.source}{alert.destination ? ` → ${alert.destination}` : ''}
          <span className="ml-2 text-white/15">{ts}</span>
        </div>
      </div>

      {/* Status */}
      <span className={cn('shrink-0 text-[9px] border px-1.5 py-0.5 rounded uppercase', STATUS_CHIP[alert.status])}>
        {alert.status}
      </span>

      {/* Actions */}
      <div className="flex items-center gap-1 shrink-0">
        {alert.status === 'NEW' && (
          <button
            onClick={() => onTriage(alert.id)}
            title="Triage"
            className="p-1 text-amber-400/60 hover:text-amber-400 hover:bg-amber-500/10 rounded transition-colors"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        )}
        <button
          onClick={() => onSeal(alert.source)}
          title="Seal host"
          className="p-1 text-red-400/60 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
        >
          <ShieldOff className="w-3 h-3" />
        </button>
        {alert.status !== 'CLOSED' && (
          <button
            onClick={() => onClose(alert.id)}
            title="Close alert"
            className="p-1 text-emerald-400/60 hover:text-emerald-400 hover:bg-emerald-500/10 rounded transition-colors"
          >
            <CheckCircle2 className="w-3 h-3" />
          </button>
        )}
        <AlertTriangle className="w-3 h-3 text-white/5" />
      </div>
    </div>
  );
}
