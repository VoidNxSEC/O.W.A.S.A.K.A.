import { motion } from 'framer-motion';
import { Network } from 'lucide-react';
import { systemLayers } from '../../lib/mock-data';
import type { SystemLayer } from '../../lib/types';
import { Card, CardContent } from '../ui/Card';

const accentClass: Record<SystemLayer['accent'], string> = {
  violet: 'accent-violet',
  emerald: 'accent-emerald',
  amber: 'accent-amber',
  blue: 'accent-blue',
  cyan: 'accent-cyan',
  slate: 'accent-slate',
};

function LayerCard({ layer, index }: { layer: SystemLayer; index: number }) {
  const Icon = layer.icon;

  return (
    <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 * index, duration: 0.5 }}>
      <Card className={`layer-card ${accentClass[layer.accent]}`}>
        <CardContent>
          <div className="layer-top">
            <span className="icon-cell">
              <Icon size={20} />
            </span>
            <code>0{index + 1}</code>
          </div>
          <h3>{layer.name}</h3>
          <p>{layer.detail}</p>
        </CardContent>
      </Card>
    </motion.div>
  );
}

export function ArchitectureMap() {
  return (
    <Card className="architecture-card">
      <CardContent>
        <div className="section-title">
          <Network size={22} />
          <div>
            <p>Architecture</p>
            <h2>Air-gapped trust topology</h2>
          </div>
        </div>

        <div className="architecture-grid">
          <div className="span-all">
            <LayerCard layer={systemLayers[0]} index={0} />
          </div>
          <div className="span-all">
            <LayerCard layer={systemLayers[1]} index={1} />
          </div>
          {systemLayers.slice(2).map((layer, index) => (
            <LayerCard key={layer.name} layer={layer} index={index + 2} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
