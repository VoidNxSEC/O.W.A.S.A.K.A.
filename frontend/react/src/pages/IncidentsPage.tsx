import { ShieldAlert } from 'lucide-react';
import { AppShell } from '../components/layout/AppShell';
import { Card, CardContent } from '../components/ui/Card';
import { useOwasakaEnvironment } from '../lib/use-owasaka-environment';

export function IncidentsPage() {
  const env = useOwasakaEnvironment();

  return (
    <AppShell>
      <section className="page-heading">
        <p>Incidents</p>
        <h1>Triage, containment and evidence collection</h1>
      </section>

      <section className="incident-grid">
        {env.incidents.length === 0 ? (
          <Card className="incident-card">
            <CardContent>
              <div className="incident-top">
                <ShieldAlert size={20} />
                <code>STANDBY</code>
              </div>
              <h2>No active critical incidents</h2>
              <div className="incident-meta">
                <span>Core: {env.coreOnline ? 'online' : 'offline'}</span>
                <span>WS: {env.wsConnected ? 'connected' : 'standby'}</span>
              </div>
              <div className="incident-footer">
                <strong>clear</strong>
                <em>monitoring</em>
              </div>
            </CardContent>
          </Card>
        ) : env.incidents.map((incident) => (
          <Card className={`incident-card severity-${incident.severity}`} key={incident.id}>
            <CardContent>
              <div className="incident-top">
                <ShieldAlert size={20} />
                <code>{incident.id}</code>
              </div>
              <h2>{incident.title}</h2>
              <div className="incident-meta">
                <span>{incident.source}</span>
                <span>{incident.target}</span>
                <span>{incident.updatedAt}</span>
              </div>
              <div className="incident-footer">
                <strong>{incident.severity}</strong>
                <em>{incident.status}</em>
              </div>
            </CardContent>
          </Card>
        ))}
      </section>
    </AppShell>
  );
}
