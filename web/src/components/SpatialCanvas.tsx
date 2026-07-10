import React, { useState, useRef } from 'react';
import type { TopologyNode, TopologyEdge, ThreatLevel } from '../types';
import { cn } from '../lib/utils';
import { GripHorizontal, Router, Server, Box, Monitor, HelpCircle, ShieldOff } from 'lucide-react';

const NODE_W = 200;
const NODE_H = 88;

interface Props {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  threatMap: Map<string, ThreatLevel>;
  onNodeMove: (id: string, x: number, y: number) => void;
  onSealHost: (ip: string) => void;
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  router: Router, host: Server, container: Box, vm: Monitor, unknown: HelpCircle,
};

const THREAT_STYLES: Record<NonNullable<ThreatLevel>, string> = {
  CRITICAL: 'border-red-500/60 bg-red-500/5 threat-critical',
  HIGH:     'border-orange-500/50 bg-orange-500/5',
  TOR:      'border-purple-500/50 bg-purple-500/5 threat-tor',
  CANARY:   'border-amber-500/50 bg-amber-500/5 threat-canary',
};

const THREAT_BADGE: Record<NonNullable<ThreatLevel>, string> = {
  CRITICAL: 'bg-red-600    text-white',
  HIGH:     'bg-orange-600 text-white',
  TOR:      'bg-purple-600 text-white',
  CANARY:   'bg-amber-600  text-black',
};

export function SpatialCanvas({ nodes, edges, threatMap, onNodeMove, onSealHost }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [camera, setCamera] = useState({ x: 0, y: 0, z: 1 });
  const [draggingCanvas, setDraggingCanvas] = useState(false);
  const [draggingNode,   setDraggingNode]   = useState<string | null>(null);
  const lastPtr = useRef({ x: 0, y: 0 });

  const onPtrDown = (e: React.PointerEvent) => {
    if (e.target === containerRef.current || (e.target as HTMLElement).id === 'canvas-bg') {
      setDraggingCanvas(true);
      lastPtr.current = { x: e.clientX, y: e.clientY };
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
    }
  };

  const onPtrMove = (e: React.PointerEvent) => {
    if (draggingCanvas) {
      const dx = e.clientX - lastPtr.current.x;
      const dy = e.clientY - lastPtr.current.y;
      setCamera(c => ({ ...c, x: c.x + dx, y: c.y + dy }));
      lastPtr.current = { x: e.clientX, y: e.clientY };
    } else if (draggingNode) {
      const dx = (e.clientX - lastPtr.current.x) / camera.z;
      const dy = (e.clientY - lastPtr.current.y) / camera.z;
      const node = nodes.find(n => n.id === draggingNode);
      if (node) onNodeMove(draggingNode, node.x + dx, node.y + dy);
      lastPtr.current = { x: e.clientX, y: e.clientY };
    }
  };

  const onPtrUp = (e: React.PointerEvent) => {
    setDraggingCanvas(false);
    setDraggingNode(null);
    if ((e.target as HTMLElement).hasPointerCapture?.(e.pointerId)) {
      (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    }
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = -e.deltaY * 0.001;
    setCamera(c => ({ ...c, z: Math.min(Math.max(0.2, c.z + delta), 3) }));
  };

  // Empty state
  if (nodes.length === 0) {
    return (
      <div
        ref={containerRef}
        className="relative w-full h-full overflow-hidden bg-[#050505] flex items-center justify-center"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
        }}
      >
        <div className="text-center">
          <div className="text-white/10 text-6xl mb-4">⊘</div>
          <p className="text-white/20 text-xs font-mono uppercase tracking-widest">
            No topology data — start the SIEM to discover hosts
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="relative w-full h-full overflow-hidden bg-[#050505]"
      onPointerDown={onPtrDown}
      onPointerMove={onPtrMove}
      onPointerUp={onPtrUp}
      onPointerLeave={onPtrUp}
      onWheel={onWheel}
    >
      <div
        id="canvas-bg"
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(to right, rgba(255,255,255,0.025) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255,255,255,0.025) 1px, transparent 1px)
          `,
          backgroundSize: `${40 * camera.z}px ${40 * camera.z}px`,
          backgroundPosition: `${camera.x}px ${camera.y}px`,
        }}
      />

      <div
        className="absolute top-0 left-0 w-full h-full origin-top-left will-change-transform"
        style={{ transform: `translate(${camera.x}px,${camera.y}px) scale(${camera.z})` }}
      >
        {/* Edges */}
        <svg style={{ position: 'absolute', top: 0, left: 0, width: 1, height: 1, overflow: 'visible', pointerEvents: 'none' }}>
          {edges.map(edge => {
            const src = nodes.find(n => n.id === edge.source);
            const tgt = nodes.find(n => n.id === edge.target);
            if (!src || !tgt) return null;
            const x1 = src.x + NODE_W;
            const y1 = src.y + NODE_H / 2;
            const x2 = tgt.x;
            const y2 = tgt.y + NODE_H / 2;
            const srcThreat = threatMap.get(src.id) ?? threatMap.get(src.label ?? '');
            const tgtThreat = threatMap.get(tgt.id) ?? threatMap.get(tgt.label ?? '');
            const hasThreat = srcThreat === 'CRITICAL' || tgtThreat === 'CRITICAL';
            const path = `M${x1} ${y1} C${x1+80} ${y1},${x2-80} ${y2},${x2} ${y2}`;
            return (
              <path
                key={edge.id}
                d={path}
                fill="none"
                stroke={hasThreat ? 'rgba(239,68,68,0.35)' : 'rgba(255,255,255,0.12)'}
                strokeWidth={hasThreat ? 2 : 1.5}
                strokeDasharray={hasThreat ? '6,3' : undefined}
              />
            );
          })}
        </svg>

        {/* Nodes */}
        {nodes.map(node => {
          const threat = threatMap.get(node.id) ?? threatMap.get(node.label ?? '');
          const Icon = TYPE_ICONS[node.type ?? 'unknown'] ?? HelpCircle;
          const isExpanded = false;
          return (
            <div
              key={node.id}
              className={cn(
                'absolute rounded-xl border bg-[#0A0A0A]/95 backdrop-blur-xl',
                'shadow-xl shadow-black/60 transition-colors duration-300 group flex flex-col',
                'hover:border-indigo-500/40',
                threat ? THREAT_STYLES[threat] : 'border-white/10',
              )}
              style={{ transform: `translate(${node.x}px,${node.y}px)`, width: NODE_W, minHeight: NODE_H }}
            >
              {/* Drag handle */}
              <div
                className="h-8 border-b border-white/10 flex items-center justify-between px-3 rounded-t-xl bg-white/5 cursor-grab active:cursor-grabbing select-none"
                onPointerDown={e => {
                  e.stopPropagation();
                  setDraggingNode(node.id);
                  lastPtr.current = { x: e.clientX, y: e.clientY };
                  containerRef.current?.setPointerCapture(e.pointerId);
                }}
              >
                <div className="flex items-center gap-2 pointer-events-none">
                  <GripHorizontal className="w-3 h-3 text-white/30" />
                  <span className="text-xs font-medium text-white/80 truncate max-w-[110px]">
                    {node.label ?? node.id}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {threat && (
                    <span className={cn('text-[9px] font-bold px-1.5 py-0.5 rounded uppercase', THREAT_BADGE[threat])}>
                      {threat}
                    </span>
                  )}
                  <Icon className="w-3 h-3 text-white/30 pointer-events-none" />
                </div>
              </div>

              {/* Body */}
              <div className="p-3 flex-1 space-y-2 pointer-events-none">
                <div className="flex justify-between text-[10px] font-mono text-white/30 uppercase">
                  <span>{node.type ?? 'unknown'}</span>
                  <span className="truncate ml-2 text-right max-w-[90px] text-white/20">{node.id}</span>
                </div>
                {(node.cpu !== undefined || node.mem !== undefined) && (
                  <div className="space-y-1.5">
                    {node.cpu !== undefined && (
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] text-white/30 w-6">CPU</span>
                        <div className="flex-1 h-0.5 bg-black/40 rounded-full overflow-hidden">
                          <div
                            className={cn('h-full rounded-full', node.cpu > 80 ? 'bg-red-500' : 'bg-indigo-500')}
                            style={{ width: `${Math.min(100, node.cpu)}%` }}
                          />
                        </div>
                        <span className="text-[9px] font-mono text-white/40">{node.cpu.toFixed(0)}%</span>
                      </div>
                    )}
                    {node.mem !== undefined && (
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] text-white/30 w-6">MEM</span>
                        <div className="flex-1 h-0.5 bg-black/40 rounded-full overflow-hidden">
                          <div
                            className={cn('h-full rounded-full', node.mem > 80 ? 'bg-red-500' : 'bg-emerald-500')}
                            style={{ width: `${Math.min(100, node.mem)}%` }}
                          />
                        </div>
                        <span className="text-[9px] font-mono text-white/40">{node.mem.toFixed(0)}%</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Seal button (visible on hover) */}
              <button
                className="opacity-0 group-hover:opacity-100 absolute bottom-2 right-2 flex items-center gap-1 px-2 py-1 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 rounded text-[9px] font-bold text-red-400 uppercase transition-all pointer-events-auto"
                onClick={e => { e.stopPropagation(); onSealHost(node.label ?? node.id); }}
              >
                <ShieldOff className="w-2.5 h-2.5" /> Seal
              </button>

              {/* Ports */}
              <div className="absolute -left-2 top-10 w-4 h-4 bg-[#0A0A0A] border-2 border-indigo-500/50 rounded-full" />
              <div className="absolute -right-2 top-10 w-4 h-4 bg-[#0A0A0A] border-2 border-indigo-500/50 rounded-full" />
            </div>
          );
        })}
      </div>

      {/* HUD */}
      <div className="absolute bottom-3 right-3 bg-black/60 backdrop-blur-md border border-white/10 rounded-lg px-3 py-1.5 text-[10px] font-mono text-white/30 pointer-events-none select-none">
        {(camera.z * 100).toFixed(0)}% • {nodes.length} nodes • scroll=zoom drag=pan
      </div>
    </div>
  );
}
