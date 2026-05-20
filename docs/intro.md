---
sidebar_position: 1
slug: /
title: O.W.A.S.A.K.A. SIEM
---

# O.W.A.S.A.K.A. SIEM

<section className="docsHero" aria-label="O.W.A.S.A.K.A. documentation overview">
  <div className="docsHero__content">
    <p className="docsHero__eyebrow">Air-gapped SIEM documentation</p>
    <h2>Operational notes for building, deploying, and running O.W.A.S.A.K.A.</h2>
    <p>
      Open Watchful Air-gapped Security Analysis Kit & Architecture is a local-first
      security monitoring platform built around isolation, provenance, and practical
      incident response.
    </p>
    <div className="docsHero__actions">
      <a className="docsButton docsButton--primary" href="architecture/OVERVIEW">Architecture</a>
      <a className="docsButton" href="deployment">Deployment</a>
    </div>
  </div>
  <div className="docsHero__panel" aria-label="Documentation status">
    <span>Current focus</span>
    <strong>Pre-production hardening</strong>
    <dl>
      <div>
        <dt>Runtime</dt>
        <dd>Go + Svelte</dd>
      </div>
      <div>
        <dt>Security</dt>
        <dd>RBAC, signing, transparency</dd>
      </div>
      <div>
        <dt>Ops</dt>
        <dd>Runbooks, backups, NixOS</dd>
      </div>
    </dl>
  </div>
</section>

<section className="docsGrid" aria-label="Primary documentation sections">
  <a className="docsCard" href="architecture/OVERVIEW">
    <span>01</span>
    <h3>Architecture</h3>
    <p>System design, data model, storage boundaries, and development phases.</p>
  </a>
  <a className="docsCard" href="auth/MODEL">
    <span>02</span>
    <h3>Identity & Authorization</h3>
    <p>Principal model, RBAC, credential operations, event signing, and rotation.</p>
  </a>
  <a className="docsCard" href="deployment">
    <span>03</span>
    <h3>Deployment</h3>
    <p>Dedicated host setup, NixOS service integration, and operational layout.</p>
  </a>
  <a className="docsCard" href="runbooks/INCIDENT">
    <span>04</span>
    <h3>Runbooks</h3>
    <p>Incident flow, disaster recovery, log analysis, and common failure paths.</p>
  </a>
</section>

<section className="docsCallout" aria-label="Quick paths">
  <div>
    <h2>Quick paths</h2>
    <p>Use these when you need a direct entry point instead of browsing the full sidebar.</p>
  </div>
  <ul>
    <li><a href="development">Development guide</a></li>
    <li><a href="api">API documentation</a></li>
    <li><a href="secrets/BOOTSTRAP">Secrets bootstrap</a></li>
    <li><a href="observability/SETUP">Observability setup</a></li>
  </ul>
</section>
