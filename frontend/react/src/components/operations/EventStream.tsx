import { AlertTriangle, CheckCircle2, RadioTower } from 'lucide-react';
import type { LiveEvent } from '../../lib/types';
import { Card, CardContent } from '../ui/Card';

const iconByType: Record<string, typeof AlertTriangle> = {
  THREAT_ALERT: AlertTriangle,
  DNS: RadioTower,
  PORT_SCAN: AlertTriangle,
  ARP: CheckCircle2,
  SYSTEM: CheckCircle2,
};

export function EventStream({ events }: { events: LiveEvent[] }) {
  return (
    <Card>
      <CardContent>
        <div className="section-title">
          <RadioTower size={22} />
          <div>
            <p>Live Intelligence</p>
            <h2>Prioritized signal stream</h2>
          </div>
        </div>

        <div className="event-stream">
          {events.length === 0 ? (
            <div className="empty-panel">
              <strong>No live events yet</strong>
              <span>Waiting for OWASAKA core WebSocket telemetry.</span>
            </div>
          ) : events.map((event) => {
            const Icon = iconByType[event.type] || RadioTower;
            return (
              <article className={`stream-event severity-${event.severity}`} key={event.id}>
                <div className="stream-icon">
                  <Icon size={18} />
                </div>
                <div>
                  <header>
                    <strong>{event.type}</strong>
                    <time>{event.time}</time>
                  </header>
                  <p>{event.summary}</p>
                  <footer>
                    <code>{event.source}</code>
                    <span>{event.target}</span>
                  </footer>
                </div>
              </article>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
