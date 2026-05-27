import { GitBranch } from 'lucide-react';
import { EvidenceRail } from '../components/evidence/EvidenceRail';
import { AppShell } from '../components/layout/AppShell';
import { Card, CardContent } from '../components/ui/Card';
import { useOwasakaEnvironment } from '../lib/use-owasaka-environment';

export function TransparencyPage() {
  const env = useOwasakaEnvironment();
  const sth = env.sth;

  return (
    <AppShell>
      <section className="page-heading">
        <p>Transparency</p>
        <h1>Signed tree heads and external verification</h1>
      </section>

      <EvidenceRail />

      <section className="table-panel">
        <Card>
          <CardContent>
            <div className="section-title">
              <GitBranch size={22} />
              <div>
                <p>Merkle Log</p>
                <h2>Recent commitments</h2>
              </div>
            </div>
            <div className="data-table">
              {sth ? (
                <div className="data-row">
                  <strong>Current STH</strong>
                  <span>{sth.tree_size.toLocaleString()} leaves</span>
                  <code>{sth.root_hash}</code>
                  <span>{new Date(Math.floor(sth.timestamp_ns / 1_000_000)).toLocaleString()}</span>
                  <em>published</em>
                </div>
              ) : (
                <div className="empty-panel">
                  <strong>No signed tree head yet</strong>
                  <span>The transparency log appears empty or the core is not reachable.</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </section>
    </AppShell>
  );
}
