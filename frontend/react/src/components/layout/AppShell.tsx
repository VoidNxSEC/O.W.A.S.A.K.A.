import { Binary } from 'lucide-react';
import type { ReactNode } from 'react';
import { Badge } from '../ui/Badge';

const links = [
  ['/', 'Overview'],
  ['/console', 'Console'],
  ['/transparency', 'Transparency'],
  ['/incidents', 'Incidents'],
];

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <main className="app-shell">
      <div className="ambient-grid" />
      <section className="page-frame">
        <nav className="top-nav" aria-label="Primary">
          <a className="brand" href="/">
            <span className="brand-mark">
              <Binary size={20} />
            </span>
            <span>
              <strong>OWASAKA</strong>
              <small>VoidNX Labs · Evidence Layer</small>
            </span>
          </a>

          <div className="nav-links">
            {links.map(([href, label]) => (
              <a className={window.location.pathname === href ? 'active' : ''} href={href} key={href}>
                {label}
              </a>
            ))}
          </div>

          <div className="nav-badges">
            <Badge>Air-gapped</Badge>
            <Badge>PKI local-first</Badge>
            <Badge tone="orange">Merkle proofs</Badge>
          </div>
        </nav>

        {children}
      </section>
    </main>
  );
}
