import React, { useEffect, useRef } from 'react';
import type { LogEntry, EventType } from '../types';
import { Terminal as TerminalIcon, ChevronRight } from 'lucide-react';
import { cn } from '../lib/utils';

const TYPE_COLOR: Partial<Record<EventType, string>> = {
  THREAT_ALERT: 'text-red-400',
  TOR:          'text-purple-400',
  CANARY:       'text-amber-400',
  PORT_SCAN:    'text-orange-400',
  DNS:          'text-cyan-400',
  ARP:          'text-emerald-400',
  PROXY:        'text-blue-400',
  VM:           'text-indigo-400',
  PHYSICAL:     'text-slate-400',
  COMPLIANCE:   'text-pink-400',
};

interface Props {
  logs: LogEntry[];
}

export function SystemTerminal({ logs }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="h-full flex flex-col font-mono text-xs bg-[#050505]">
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-3 space-y-0.5 scrollbar-hide"
      >
        {logs.length === 0 && (
          <div className="text-white/15 italic text-[10px]">
            Waiting for pipeline events...
          </div>
        )}
        {logs.map((log, i) => {
          const color =
            log.eventType ? (TYPE_COLOR[log.eventType] ?? 'text-white/60') :
            log.type === 'error'  ? 'text-red-400' :
            log.type === 'warn'   ? 'text-amber-400' :
            log.type === 'system' ? 'text-indigo-400' :
            'text-white/60';

          return (
            <div key={i} className="flex gap-2 leading-relaxed">
              <span className="text-white/15 shrink-0 select-none">
                {new Date(log.timestamp).toLocaleTimeString('en', { hour12: false })}
              </span>
              <span className={cn('flex-1', color)}>
                <span className="text-white/20 mr-1 select-none">›</span>
                {log.message}
              </span>
            </div>
          );
        })}
        <div className="flex items-center gap-1 text-indigo-400/40 animate-pulse mt-1">
          <ChevronRight className="w-3 h-3" />
          <span className="w-2 h-3.5 bg-indigo-400/40 rounded-sm inline-block" />
        </div>
      </div>
    </div>
  );
}
