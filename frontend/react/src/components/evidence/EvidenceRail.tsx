import { CheckCircle2, Zap } from 'lucide-react';
import { evidenceFlow } from '../../lib/mock-data';
import { Badge } from '../ui/Badge';
import { Card, CardContent } from '../ui/Card';

export function EvidenceRail() {
  return (
    <Card className="evidence-card">
      <CardContent>
        <div className="panel-header">
          <div>
            <p>Evidence Pipeline</p>
            <h2>From event to proof</h2>
          </div>
          <Badge tone="green">Verifiable</Badge>
        </div>

        <div className="evidence-grid">
          {evidenceFlow.map((step, index) => (
            <div className="evidence-step" key={step.label}>
              <div>
                <code>{String(index + 1).padStart(2, '0')}</code>
                {index < evidenceFlow.length - 1 ? <Zap size={16} /> : <CheckCircle2 size={16} />}
              </div>
              <strong>{step.label}</strong>
              <span>{step.description}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
