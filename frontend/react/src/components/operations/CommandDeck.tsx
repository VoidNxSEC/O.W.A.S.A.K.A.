import { Activity, Network, Radar, ShieldCheck } from 'lucide-react';
import type { SensorSurface } from '../../lib/types';
import { Card, CardContent } from '../ui/Card';

export function CommandDeck({
  coreOnline,
  lastError,
  sensorSurfaces,
}: {
  coreOnline: boolean;
  lastError?: string | null;
  sensorSurfaces: SensorSurface[];
}) {
  return (
    <Card className="command-deck">
      <CardContent>
        <div className="deck-header">
          <div>
            <p>Command Deck</p>
            <h2>Air-gapped operating picture</h2>
          </div>
          <span className={`deck-status ${coreOnline ? '' : 'deck-status-offline'}`}>
            <ShieldCheck size={16} />
            {coreOnline ? 'Core online' : 'Core offline'}
          </span>
        </div>

        <div className="radar-stage" aria-label="OWASAKA coverage radar">
          <div className="radar-core">
            <Radar size={34} />
            <span>OWASAKA</span>
          </div>
          <span className="orbit orbit-a">DNS</span>
          <span className="orbit orbit-b">DPI</span>
          <span className="orbit orbit-c">PKI</span>
          <span className="orbit orbit-d">STH</span>
          <span className="orbit orbit-e">NAS</span>
        </div>

        <div className="surface-list">
          {sensorSurfaces.map((surface) => (
            <div className={`surface-row surface-${surface.status}`} key={surface.name}>
              <div>
                <Network size={16} />
                <span>{surface.name}</span>
              </div>
              <strong>{surface.coverage}%</strong>
              <em style={{ width: `${surface.coverage}%` }} />
            </div>
          ))}
        </div>

        <div className="deck-footer">
          <Activity size={16} />
          <span>{lastError || 'Telemetry normalized, signed, and queued for Merkle commitment.'}</span>
        </div>
      </CardContent>
    </Card>
  );
}
