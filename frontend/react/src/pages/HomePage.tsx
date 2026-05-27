import { motion } from 'framer-motion';
import { LockKeyhole } from 'lucide-react';
import { ArchitectureMap } from '../components/architecture/ArchitectureMap';
import { EvidenceRail } from '../components/evidence/EvidenceRail';
import { AppShell } from '../components/layout/AppShell';
import { CommandDeck } from '../components/operations/CommandDeck';
import { EventStream } from '../components/operations/EventStream';
import { ResponseLane } from '../components/operations/ResponseLane';
import { TerminalPanel } from '../components/terminal/TerminalPanel';
import { Button } from '../components/ui/Button';
import { Card, CardContent } from '../components/ui/Card';
import { useOwasakaEnvironment } from '../lib/use-owasaka-environment';

export function HomePage() {
  const env = useOwasakaEnvironment();

  return (
    <AppShell>
      <section className="hero-grid">
        <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }}>
          <div className="hero-kicker">
            <LockKeyhole size={15} />
            Provenance-first SIEM
          </div>

          <h1>When zero-days become accountable.</h1>
          <p className="hero-copy">
            A local-first security observability layer where critical events are signed, timestamped, Merkle-linked, and independently verifiable without turning raw logs into public data.
          </p>

          <div className="hero-actions">
            <a href="/console">
              <Button>Open console</Button>
            </a>
            <a href="/transparency">
              <Button variant="outline">View transparency log</Button>
            </a>
          </div>

          <div className="stat-grid">
            {env.consoleStats.map((stat) => (
              <Card className="stat-card" key={stat.label}>
                <CardContent>
                  <strong>{stat.value}</strong>
                  <span>{stat.label}</span>
                  <code>{stat.hint}</code>
                </CardContent>
              </Card>
            ))}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.7, delay: 0.1 }}>
          <CommandDeck coreOnline={env.coreOnline} lastError={env.lastError} sensorSurfaces={env.sensorSurfaces} />
        </motion.div>
      </section>

      <section className="two-column">
        <ArchitectureMap />
        <div className="stack">
          <EventStream events={env.events.slice(0, 6)} />
          <ResponseLane actions={env.responseActions} />
          <EvidenceRail />
          <Card>
            <CardContent>
              <div className="section-title">
                <LockKeyhole size={22} />
                <div>
                  <p>Trust Boundary</p>
                  <h2>Separated signing domains</h2>
                </div>
              </div>
              <div className="domain-list">
                {[
                  ['JWT signer', 'sessions and service auth'],
                  ['Event signer', 'canonical NetworkEvent signatures'],
                  ['STH signer', 'Merkle root commitments'],
                ].map(([title, body]) => (
                  <div key={title}>
                    <strong>{title}</strong>
                    <span>{body}</span>
                  </div>
                ))}
              </div>
              <p className="callout">Compromise is contained by purpose. A broken token signer does not forge events; a broken event signer does not forge signed tree heads.</p>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="terminal-band">
        <TerminalPanel />
      </section>
    </AppShell>
  );
}
