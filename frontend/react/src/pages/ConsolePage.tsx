import { Activity, ShieldCheck } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { CommandDeck } from '../components/operations/CommandDeck';
import { EventStream } from '../components/operations/EventStream';
import { ResponseLane } from '../components/operations/ResponseLane';
import { TerminalPanel } from '../components/terminal/TerminalPanel';
import { Card, CardContent } from '../components/ui/Card';
import { useOwasakaEnvironment } from '../lib/use-owasaka-environment';

export function ConsolePage() {
  const env = useOwasakaEnvironment();

  return (
    <AppShell>
      <section className="page-heading">
        <p>Operator Console</p>
        <h1>Live authority and event posture</h1>
      </section>

      <section className="console-grid">
        <CommandDeck coreOnline={env.coreOnline} lastError={env.lastError} sensorSurfaces={env.sensorSurfaces} />
        <div className="stack">
          <EventStream events={env.events} />
          <Card>
            <CardContent>
              <div className="section-title">
                <Activity size={22} />
                <div>
                  <p>Runtime</p>
                  <h2>Core status</h2>
                </div>
              </div>
              <div className="status-list">
                {env.consoleStats.map((stat) => (
                  <div key={stat.label}>
                    <span>{stat.label}</span>
                    <strong>{stat.value}</strong>
                    <code>{stat.hint}</code>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <div className="section-title">
                <ShieldCheck size={22} />
                <div>
                  <p>Controls</p>
                  <h2>Operator actions</h2>
                </div>
              </div>
              <div className="action-list">
                <button>Seal host</button>
                <button>Export case</button>
                <button>Verify STH</button>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="two-column compact-section">
        <TerminalPanel />
        <ResponseLane actions={env.responseActions} />
      </section>
    </AppShell>
  );
}
