import { fingerprints } from '../../lib/mock-data';
import { Card, CardContent } from '../ui/Card';

function AccentLine() {
  return <div className="accent-line" />;
}

export function TerminalPanel() {
  return (
    <Card className="terminal-card">
      <CardContent className="terminal-content">
        <div className="terminal-bar">
          <div className="window-dots" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <span>oswaka status --pki</span>
        </div>

        <div className="terminal-body">
          <div className="terminal-bg" />
          <div className="terminal-stack">
            <div className="prompt">
              <span>owasaka@core</span>
              <em> ~ $ </em>
              <strong>oswaka status --pki</strong>
            </div>

            <AccentLine />

            <div className="ready-line">OWASAKA stands ready.</div>

            <div className="fingerprints">
              {fingerprints.map((item) => {
                const Icon = item.icon;
                return (
                  <div className="fingerprint-row" key={item.label}>
                    <Icon size={20} />
                    <span>{item.label}</span>
                    <code>{item.value}</code>
                  </div>
                );
              })}
            </div>

            <div className="trust-box">
              <div className="trust-copy">
                <span>?</span>
                <div>
                  <p>Trust this fingerprint?</p>
                  <small>compare to ops record before accepting authority state</small>
                </div>
              </div>
              <div className="trust-actions">
                <p>› [y] Yes, trust this fingerprint</p>
                <p>[n] No, investigate / do not trust</p>
                <p>[v] View full certificate information</p>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
