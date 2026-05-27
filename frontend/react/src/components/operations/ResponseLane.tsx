import { ClipboardCheck } from 'lucide-react';
import type { ResponseAction } from '../../lib/types';
import { Card, CardContent } from '../ui/Card';

export function ResponseLane({ actions }: { actions: ResponseAction[] }) {
  return (
    <Card>
      <CardContent>
        <div className="section-title">
          <ClipboardCheck size={22} />
          <div>
            <p>Response Lane</p>
            <h2>Incident workflow</h2>
          </div>
        </div>

        <div className="response-lane">
          {actions.map((action) => (
            <div className={`response-step response-${action.tone}`} key={action.label}>
              <span>{action.label}</span>
              <strong>{action.count}</strong>
            </div>
          ))}
        </div>

        <div className="response-actions">
          <button type="button">Seal host</button>
          <button type="button">Collect evidence</button>
          <button type="button">Publish STH</button>
        </div>
      </CardContent>
    </Card>
  );
}
