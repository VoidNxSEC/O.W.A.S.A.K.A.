# OWASAKA — TODO / Roadmap de Implementação

> Gerado em: 2026-03-26
> Estado base: Milestone 4 (Correlation Engine) + Milestone 5 (SvelteKit UI) completos

---

## Legenda

| Símbolo | Significado               |
| ------- | ------------------------- |
| ✅      | Implementado              |
| 🔨      | Em andamento              |
| ⏳      | Pendente                  |
| 🔒      | Bloqueado por dependência |

---

## Sprint 0 — Fix Crítico

| #   | Tarefa                | Status | Detalhes                                                            |
| --- | --------------------- | ------ | ------------------------------------------------------------------- |
| 1   | **Fix build libpcap** | ⏳     | Adicionar `libpcap` ao `flake.nix`. Build falha em `gopacket/pcap`. |

---

## Sprint 1 — Network Intelligence (completar Phase 1)

| #   | Tarefa                                        | Status | Localização                  |
| --- | --------------------------------------------- | ------ | ---------------------------- |
| 2   | **Network Topology Mapper**                   | ⏳     | `internal/network/topology/` |
|     | `graph.go` — estrutura nodes/edges            | ⏳     |                              |
|     | `builder.go` — constrói de assets descobertos | ⏳     |                              |
|     | `differ.go` — detecção de mudanças            | ⏳     |                              |
|     | `visualizer.go` — JSON para o D3 frontend     | ⏳     |                              |
| 4   | **Transparent Proxy Engine**                  | ⏳     | `internal/network/proxy/`    |
|     | `proxy.go` — servidor HTTP/HTTPS              | ⏳     |                              |
|     | `interceptor.go` — request/response logging   | ⏳     |                              |
|     | `tls.go` — mTLS + CA local auto-gerada        | ⏳     |                              |
|     | `dpi.go` — Deep Packet Inspection hooks       | ⏳     |                              |
|     | `protocol.go` — detecção de protocolo         | ⏳     |                              |

**Deps Phase 1:**

```
go get github.com/elazarl/goproxy
go get golang.org/x/net/http2
```

---

## Sprint 2 — Analytics (completar Phase 6)

| #   | Tarefa                                    | Status | Localização                          |
| --- | ----------------------------------------- | ------ | ------------------------------------ |
| 3   | **Stream Processor**                      | ⏳     | `internal/analytics/stream/`         |
|     | `processor.go` — orquestrador             | ⏳     |                                      |
|     | `buffer.go` — buffer circular 10k eventos | ⏳     |                                      |
|     | `window.go` — sliding window 1/5/15min    | ⏳     |                                      |
|     | `normalizer.go` — normalização canônica   | ⏳     |                                      |
| 11  | **ML Anomaly Detector**                   | 🔒     | `internal/analytics/ml/` (requer #3) |
|     | `detector.go` — orquestrador              | ⏳     |                                      |
|     | `statistical.go` — z-score, EWMA          | ⏳     |                                      |
|     | `isolation_forest.go` — Isolation Forest  | ⏳     |                                      |
|     | `baseline.go` — behavioral baselining 24h | ⏳     |                                      |

---

## Sprint 3 — Asset Discovery (completar Phase 2)

| #   | Tarefa                                  | Status | Localização                                  |
| --- | --------------------------------------- | ------ | -------------------------------------------- |
| 5   | **VM Scanner**                          | ⏳     | `internal/discovery/virtual/`                |
|     | `vm_scanner.go` — orquestrador          | ⏳     |                                              |
|     | `libvirt.go` — integração libvirt       | ⏳     |                                              |
|     | `vmware.go` — stub VMware vSphere       | ⏳     |                                              |
| 6   | **Continuous Reconciliation Engine**    | 🔒     | `internal/discovery/reconciler/` (requer #5) |
|     | `reconciler.go` — scheduler de re-scans | ⏳     |                                              |
|     | `differ.go` — diff de estado            | ⏳     |                                              |
|     | `scheduler.go` — cron-like interno      | ⏳     |                                              |
|     | `alerter.go` — diffs → EventAlert       | ⏳     |                                              |

**Deps Phase 2:**

```
go get libvirt.org/go/libvirt
```

---

## Sprint 4 — Browser Security (completar Phase 3)

| #   | Tarefa                                     | Status | Localização                                |
| --- | ------------------------------------------ | ------ | ------------------------------------------ |
| 7   | **Browser Policy Enforcer**                | ⏳     | `internal/browser/policies/`               |
|     | `enforcer.go` — aplica políticas ao perfil | ⏳     |                                            |
|     | `hardening.go` — gera `user.js`            | ⏳     |                                            |
|     | `extensions.go` — lockdown whitelist       | ⏳     |                                            |
| 8   | **Browser Automation**                     | 🔒     | `internal/browser/automation/` (requer #7) |
|     | `driver.go` — WebDriver/geckodriver        | ⏳     |                                            |
|     | `capture.go` — screenshots + HAR           | ⏳     |                                            |
|     | `forensics.go` — event logging forense     | ⏳     |                                            |

**Deps Phase 3:**

```
go get github.com/tebeka/selenium
```

---

## Sprint 5 — Storage & Integridade (completar Phase 5)

| #   | Tarefa                                  | Status | Localização                               |
| --- | --------------------------------------- | ------ | ----------------------------------------- |
| 9   | **NAS Connector**                       | ⏳     | `internal/storage/nas/`                   |
|     | `connector.go` — gerenciador NFS/SMB    | ⏳     |                                           |
|     | `nfs.go` — cliente NFS                  | ⏳     |                                           |
|     | `smb.go` — cliente SMB/CIFS             | ⏳     |                                           |
|     | `healthcheck.go` — reconexão automática | ⏳     |                                           |
| 10  | **Integrity Verifier**                  | 🔒     | `internal/storage/integrity/` (requer #9) |
|     | `verifier.go` — orquestrador            | ⏳     |                                           |
|     | `merkle.go` — Merkle tree SHA-256       | ⏳     |                                           |
|     | `audit.go` — append-only audit log      | ⏳     |                                           |
|     | `snapshot.go` — snapshots + root hash   | ⏳     |                                           |

---

## Mapa de Dependências

```
#1 fix build
    └─► #2 topology mapper
    └─► #3 stream processor ──► #11 ML detector
    └─► #4 transparent proxy
    └─► #5 VM scanner ──────► #6 reconciliation
    └─► #7 policy enforcer ─► #8 browser automation
    └─► #9 NAS connector ───► #10 integrity verifier
```

---

## O que já está pronto ✅

| Subsistema                   | Localização                            |
| ---------------------------- | -------------------------------------- |
| DNS Resolver                 | `internal/network/dns/`                |
| Network Discovery (ARP/ICMP) | `internal/network/discovery/`          |
| Physical Enumerator          | `internal/discovery/physical/`         |
| Container/Docker Scanner     | `internal/discovery/virtual/docker.go` |
| Attack Surface Scanner       | `internal/discovery/attack_surface/`   |
| Correlation Engine           | `internal/analytics/correlation/`      |
| API Server + WebSocket Hub   | `internal/api/`                        |
| Firefox Launcher             | `internal/browser/firefox/`            |
| Crypto Vault (AES-256-GCM)   | `internal/storage/crypto/`             |
| BoltDB Repository            | `internal/storage/db/`                 |
| Event Pipeline               | `internal/events/`                     |
| SvelteKit UI + D3 Topology   | `web/src/`                             |
| App Orchestrator             | `internal/app/app.go`                  |
| Config System (YAML)         | `pkg/config/`                          |

---

## Performance Targets (Phase 6+)

| Métrica                 | Target    |
| ----------------------- | --------- |
| UI response (p95)       | &lt;100ms |
| Memory idle             | &lt;500MB |
| DNS lookup              | &lt;100ms |
| Port scan (65535)       | &lt;60s   |
| Events/sec stream       | >10.000   |
| Anomaly false positives | &lt;5%    |

---

**Próxima tarefa:** `#1 — Fix build libpcap`
