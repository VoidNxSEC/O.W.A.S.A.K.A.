<script lang="ts">
    import { networkEvents, isConnected, lastSeenByType, getApiBase } from '$lib/websocket';
    import { fade, slide, fly } from 'svelte/transition';
    import ThreatBanner from '$lib/ThreatBanner.svelte';
    import TopologyGraph from '$lib/TopologyGraph.svelte';
    import EventDetail from '$lib/EventDetail.svelte';

    // ── Derived state ──────────────────────────────────────────────────────────
    const visibleEvents = $derived($networkEvents.slice(0, 14));
    const threatCount   = $derived($networkEvents.filter(e => e.type === 'THREAT_ALERT').length);
    const uniqueSources = $derived(new Set($networkEvents.map(e => e.source || e.metadata?.source).filter(Boolean)).size);
    const latestEvent   = $derived($networkEvents[0]);

    const killChainCount = $derived($networkEvents.filter(e => e.metadata?.mitre_tactic).length);

    // Incident flow: real counts from event stream
    const newAlerts      = $derived($networkEvents.filter(e => e.type === 'THREAT_ALERT' && isRecent(e, 2 * 60)).length);
    const criticalAlerts = $derived($networkEvents.filter(e => e.type === 'THREAT_ALERT' && e.metadata?.severity === 'CRITICAL').length);
    const chainAlerts    = $derived(killChainCount);
    const artifactCount  = $derived(
        new Set(
            $networkEvents
                .flatMap(e => (e.metadata?.chain_events as string[] | undefined) ?? [])
        ).size
    );

    const responseStages = $derived([
        { label: 'New alerts',   value: newAlerts,      state: newAlerts > 0 ? 'active' : 'muted' },
        { label: 'Critical',     value: criticalAlerts, state: criticalAlerts > 0 ? 'warning' : 'muted' },
        { label: 'Kill chains',  value: chainAlerts,    state: chainAlerts > 0 ? 'warning' : 'calm' },
        { label: 'Artifacts',    value: artifactCount,  state: artifactCount > 0 ? 'calm' : 'muted' },
    ]);

    // Watched surfaces: active/idle/offline based on last-seen event time
    const SURFACE_MAP: Record<string, string[]> = {
        'DNS':            ['DNS'],
        'ARP':            ['ARP'],
        'Proxy DPI':      ['PROXY'],
        'VM inventory':   ['VM'],
        'Physical bus':   ['PHYSICAL'],
        'Tor detection':  ['TOR'],
        'Canary tokens':  ['CANARY', 'THREAT_ALERT'],
    };

    function surfaceState(types: string[]): 'active' | 'idle' | 'offline' {
        const now = Date.now();
        const lastSeen = Math.max(0, ...types.map(t => $lastSeenByType[t] ?? 0));
        if (lastSeen === 0) return 'offline';
        const age = now - lastSeen;
        if (age < 5 * 60 * 1000) return 'active';
        if (age < 15 * 60 * 1000) return 'idle';
        return 'offline';
    }

    // ── Event detail drawer ────────────────────────────────────────────────────
    let selectedEvent: any = $state(null);

    function openDetail(event: any) { selectedEvent = event; }
    function closeDetail() { selectedEvent = null; }

    // ── Helpers ────────────────────────────────────────────────────────────────
    function isRecent(event: any, minutes: number): boolean {
        const ts = new Date(event.timestamp || 0).getTime();
        return Date.now() - ts < minutes * 60 * 1000;
    }

    function getEventColor(type: string) {
        const c: Record<string, string> = {
            THREAT_ALERT: '#ff3333', PORT_SCAN: '#ff9900', DNS: '#00ffff',
            ARP: '#33ff33', TOR: '#9a7cff', CANARY: '#f2b84b',
            VM: '#b7e26b', PROXY: '#6f7f87',
        };
        return c[type] ?? '#cccccc';
    }

    function getEventBackground(type: string) {
        if (type === 'THREAT_ALERT') return 'rgba(255, 51, 51, 0.15)';
        if (type === 'TOR')          return 'rgba(154, 124, 255, 0.08)';
        if (type === 'CANARY')       return 'rgba(242, 184, 75, 0.08)';
        return 'rgba(0,0,0,0.5)';
    }

    function getEventClass(type = '') {
        if (type === 'THREAT_ALERT') return 'critical';
        if (type === 'PORT_SCAN')    return 'warning';
        if (type === 'DNS')          return 'info';
        if (type === 'ARP')          return 'good';
        return 'neutral';
    }

    function eventKey(event: any, index: number) {
        return event.id || `${event.type || 'event'}-${event.timestamp || 'pending'}-${index}`;
    }

    function formatTime(value: string | number | undefined) {
        return new Date(value || Date.now()).toLocaleTimeString();
    }

    function eventSummary(event: any): string {
        if (event.metadata?.rule)   return event.metadata.rule;
        if (event.metadata?.name)   return event.metadata.name;
        if (event.metadata?.domain) return event.metadata.domain;
        if (event.source)           return event.source;
        return '';
    }

    // ── Export Case ────────────────────────────────────────────────────────────
    function exportCase() {
        const caseData = {
            exported_at: new Date().toISOString(),
            siem:        'O.W.A.S.A.K.A.',
            total_events: $networkEvents.length,
            alerts:  $networkEvents.filter(e => e.type === 'THREAT_ALERT'),
            chains:  $networkEvents.filter(e => e.metadata?.mitre_tactic),
            timeline: $networkEvents,
        };
        const blob = new Blob([JSON.stringify(caseData, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `owasaka-case-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ── Seal Host ──────────────────────────────────────────────────────────────
    let sealModal = $state(false);
    let sealIp    = $state('');
    let sealState: 'idle' | 'confirming' | 'done' | 'copied' = $state('idle');

    const threatIps = $derived(
        [...new Set($networkEvents.filter(e => e.type === 'THREAT_ALERT' && e.destination).map(e => e.destination))]
    );

    async function confirmSeal() {
        if (!sealIp) return;
        try {
            const resp = await fetch(`${getApiBase()}/api/incidents/containment`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${sessionStorage.getItem('oswaka_token') ?? ''}` },
                body: JSON.stringify({ ip: sealIp }),
            });
            sealState = resp.ok ? 'done' : 'confirming';
        } catch {
            sealState = 'confirming';
        }
    }

    function nftCommand(ip: string) {
        return `nft add rule inet filter input ip saddr ${ip} drop`;
    }

    function copyNft() {
        if (!sealIp) return;
        navigator.clipboard.writeText(nftCommand(sealIp));
        sealState = 'copied';
        setTimeout(() => { sealState = 'confirming'; }, 1800);
    }

    function openSeal() { sealModal = true; sealState = 'idle'; sealIp = threatIps[0] ?? ''; }
    function closeSeal() { sealModal = false; sealState = 'idle'; }
</script>

<svelte:head>
    <title>O.W.A.S.A.K.A. Command Center</title>
</svelte:head>

<ThreatBanner />

{#if selectedEvent}
    <EventDetail event={selectedEvent} onclose={closeDetail} />
{/if}

<!-- Seal Host modal -->
{#if sealModal}
    <div class="modal-backdrop" onclick={closeSeal} onkeydown={(e) => e.key === 'Escape' && closeSeal()} role="presentation" aria-hidden="true" transition:fade={{ duration: 150 }}>
        <div class="modal-box" onclick={(e) => e.stopPropagation()} role="dialog" tabindex="-1" aria-label="Seal host" onkeydown={(e) => e.key === 'Escape' && closeSeal()} transition:fly={{ y: -20, duration: 200 }}>
            <div class="modal-header">
                <span>🔒 Seal Host</span>
                <button onclick={closeSeal} class="modal-close">✕</button>
            </div>
            <div class="modal-body">
                <label class="modal-label" for="seal-ip-select">Select threat source IP:</label>
                {#if threatIps.length > 0}
                    <div class="ip-grid">
                        {#each threatIps as ip}
                            <button
                                class="ip-chip {sealIp === ip ? 'selected' : ''}"
                                onclick={() => { sealIp = ip; sealState = 'idle'; }}
                            >{ip}</button>
                        {/each}
                    </div>
                {:else}
                    <p class="modal-hint">No THREAT_ALERT sources in current window.</p>
                {/if}

                <label class="modal-label" for="seal-ip-input">Or enter IP manually:</label>
                <input
                    id="seal-ip-input"
                    type="text"
                    class="modal-input"
                    bind:value={sealIp}
                    placeholder="10.0.0.0"
                    onchange={() => sealState = 'idle'}
                />

                {#if sealState === 'done'}
                    <div class="modal-success">✅ Containment request sent to SIEM.</div>
                {:else if sealState === 'confirming' || sealState === 'copied'}
                    <div class="nft-block">
                        <div class="nft-label">nftables command (copy & run as root):</div>
                        <code class="nft-cmd">{nftCommand(sealIp || 'IP_ADDRESS')}</code>
                        <button onclick={copyNft} class="nft-copy-btn">
                            {sealState === 'copied' ? '✓ Copied!' : 'Copy command'}
                        </button>
                    </div>
                {/if}
            </div>
            <div class="modal-footer">
                <button onclick={confirmSeal} class="modal-action" disabled={!sealIp}>
                    Send to SIEM
                </button>
                <button onclick={copyNft} class="modal-action secondary" disabled={!sealIp}>
                    Copy nftables
                </button>
            </div>
        </div>
    </div>
{/if}

<main class="command-shell">
    <header class="command-header">
        <div class="title-block">
            <span class="eyebrow">Air-gapped SIEM</span>
            <h1>O.W.A.S.A.K.A.</h1>
            <p>Command Center for network intelligence, asset drift and threat containment.</p>
        </div>
        <div class="status-badge {$isConnected ? 'online' : 'offline'}">
            <span class="status-dot"></span>
            {$isConnected ? 'Core link online' : 'Core link offline'}
        </div>
    </header>

    <section class="metric-strip" aria-label="Operational metrics">
        <article>
            <span>Events</span>
            <strong>{$networkEvents.length}</strong>
            <small>last 500 retained</small>
        </article>
        <article>
            <span>Critical</span>
            <strong class="{threatCount > 0 ? 'metric-critical' : ''}">{threatCount}</strong>
            <small>threat alerts</small>
        </article>
        <article>
            <span>Sources</span>
            <strong>{uniqueSources}</strong>
            <small>reporting nodes</small>
        </article>
        <article>
            <span>Kill Chains</span>
            <strong class="{killChainCount > 0 ? 'metric-warn' : ''}">{killChainCount}</strong>
            <small>{latestEvent ? formatTime(latestEvent.timestamp) : '--:--:--'}</small>
        </article>
    </section>

    <section class="dashboard-grid">
        <section class="panel feed-panel" aria-labelledby="feed-title">
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">Live queue</span>
                    <h2 id="feed-title">Intelligence Feed</h2>
                </div>
                <div class="feed-count">{visibleEvents.length} shown</div>
            </div>

            <div class="event-list">
                {#each visibleEvents as event, index (eventKey(event, index))}
                    <div
                        class="event-card {getEventClass(event.type)} animate-enter"
                        style="--event-color: {getEventColor(event.type)}; --event-bg: {getEventBackground(event.type)}"
                        transition:slide
                        onclick={() => openDetail(event)}
                        role="button"
                        tabindex="0"
                        onkeydown={(e) => e.key === 'Enter' && openDetail(event)}
                        aria-label="View event detail"
                    >
                        <div class="event-header">
                            <span>
                                {#if event.metadata?.mitre_tactic}⛓️ {/if}
                                {event.type || 'SYSTEM'}
                            </span>
                            <time>{formatTime(event.timestamp)}</time>
                        </div>
                        <div class="event-summary">
                            {#if event.metadata?.severity}
                                <span class="sev-pill" style="color: {getEventColor(event.type)}">{event.metadata.severity}</span>
                            {/if}
                            <span class="event-detail-text">{eventSummary(event)}</span>
                            {#if event.source}<span class="event-src">{event.source}</span>{/if}
                        </div>
                    </div>
                {/each}

                {#if visibleEvents.length === 0}
                    <div class="empty-state" transition:fade>
                        <strong>No telemetry received</strong>
                        <span>Waiting on SIEM core stream.</span>
                        <code>{$isConnected ? 'Connected — no events yet' : 'Connecting…'}</code>
                    </div>
                {/if}
            </div>
        </section>

        <aside class="side-stack">
            <section class="panel topology-panel" aria-labelledby="topology-title">
                <div class="panel-heading">
                    <div>
                        <span class="eyebrow">Live map</span>
                        <h2 id="topology-title">Network Topology</h2>
                    </div>
                </div>
                <TopologyGraph />
            </section>

            <section class="panel response-panel" aria-labelledby="response-title">
                <div class="panel-heading">
                    <div>
                        <span class="eyebrow">Response lane</span>
                        <h2 id="response-title">Incident Flow</h2>
                    </div>
                </div>

                <div class="stage-list">
                    {#each responseStages as stage}
                        <div class="stage-row {stage.state}">
                            <span>{stage.label}</span>
                            <strong>{stage.value}</strong>
                        </div>
                    {/each}
                </div>

                <div class="control-row">
                    <button type="button" onclick={openSeal} class="{threatIps.length > 0 ? 'btn-danger' : ''}">
                        🔒 Seal Host
                    </button>
                    <button type="button" onclick={exportCase}>
                        ⬇ Export Case
                    </button>
                </div>
            </section>
        </aside>
    </section>

    <section class="surface-band" aria-label="Watched surfaces">
        {#each Object.entries(SURFACE_MAP) as [label, types]}
            {@const state = surfaceState(types)}
            <span class="surface-chip surface-{state}">
                <span class="surface-dot"></span>
                {label}
            </span>
        {/each}
    </section>
</main>

<style>
    .command-shell {
        width: min(1480px, calc(100vw - 32px));
        margin: 0 auto;
        padding: 28px 0 40px;
        display: flex;
        flex-direction: column;
        gap: 20px;
    }

    .command-header {
        min-height: 180px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 20px;
        padding: clamp(20px, 4vw, 34px);
        border: 1px solid var(--border);
        border-radius: 8px;
        background:
            linear-gradient(135deg, rgba(39, 215, 196, 0.13), transparent 42%),
            linear-gradient(180deg, rgba(255, 255, 255, 0.035), transparent),
            var(--panel);
        box-shadow: var(--shadow);
    }

    .title-block { max-width: 760px; }

    .eyebrow {
        display: block;
        margin-bottom: 8px;
        color: var(--accent-cyan);
        font-family: var(--font-mono);
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    h1 {
        margin: 0 0 10px;
        font-size: clamp(2.4rem, 7vw, 5.8rem);
        line-height: 0.88;
    }

    .title-block p {
        max-width: 650px;
        margin: 0;
        color: var(--fg-muted);
        font-size: clamp(1rem, 1.4vw, 1.15rem);
    }

    .metric-strip {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
    }

    .metric-strip article,
    .panel {
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--panel);
        box-shadow: var(--shadow);
    }

    .metric-strip article {
        min-height: 112px;
        padding: 16px;
        display: grid;
        align-content: space-between;
    }

    .metric-strip span, .metric-strip small {
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.76rem;
    }

    .metric-strip strong {
        color: var(--fg-base);
        font-family: var(--font-mono);
        font-size: clamp(1.65rem, 3vw, 2.2rem);
        line-height: 1;
    }

    .metric-critical { color: #ff3333 !important; }
    .metric-warn     { color: #ff9900 !important; }

    .dashboard-grid {
        display: grid;
        grid-template-columns: minmax(0, 1.5fr) minmax(360px, 0.8fr);
        gap: 20px;
        align-items: stretch;
    }

    .panel { padding: 16px; }

    .panel-heading {
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: flex-start;
        margin-bottom: 14px;
    }

    h2 { margin: 0; font-size: 1.05rem; }

    .feed-count {
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.78rem;
    }

    .feed-panel { min-height: 680px; }

    .event-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-height: 620px;
        overflow-y: auto;
        padding-right: 4px;
    }

    .event-card {
        border: 1px solid color-mix(in srgb, var(--event-color) 35%, var(--border));
        border-left: 3px solid var(--event-color);
        border-radius: 8px;
        padding: 12px;
        background: var(--event-bg);
        cursor: pointer;
    }

    .event-card:hover {
        border-color: color-mix(in srgb, var(--event-color) 58%, var(--border));
        transform: translateY(-1px);
    }

    .event-header {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 6px;
        font-family: var(--font-mono);
        font-size: 0.78rem;
        font-weight: 700;
    }

    .event-header span { color: var(--event-color); overflow-wrap: anywhere; }
    .event-header time { color: var(--fg-muted); white-space: nowrap; }

    .event-summary {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }

    .sev-pill {
        font-family: var(--font-mono);
        font-size: 0.68rem;
        font-weight: 700;
        padding: 1px 6px;
        border: 1px solid currentColor;
        border-radius: 3px;
        opacity: 0.8;
    }

    .event-detail-text {
        color: var(--fg-base);
        font-family: var(--font-mono);
        font-size: 0.8rem;
        overflow-wrap: anywhere;
        flex: 1;
    }

    .event-src {
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.72rem;
        white-space: nowrap;
    }

    .empty-state {
        min-height: 220px;
        display: grid;
        place-items: center;
        gap: 8px;
        text-align: center;
        border: 1px dashed var(--border);
        border-radius: 8px;
        color: var(--fg-muted);
        background: rgba(0, 0, 0, 0.18);
    }

    .empty-state strong { color: var(--fg-base); }
    .empty-state code  { color: var(--accent-cyan); font-family: var(--font-mono); }

    .side-stack {
        display: grid;
        gap: 20px;
        grid-template-rows: minmax(420px, 1fr) auto;
    }

    .topology-panel { min-height: 460px; }
    .response-panel { min-height: 250px; }

    .stage-list { display: grid; gap: 8px; }

    .stage-row {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--panel-strong);
        font-family: var(--font-mono);
        font-size: 0.8rem;
    }

    .stage-row strong { color: var(--fg-base); }
    .stage-row.active  { border-color: rgba(39, 215, 196, 0.45); }
    .stage-row.warning { border-color: rgba(242, 184, 75, 0.48); }
    .stage-row.calm    { border-color: rgba(183, 226, 107, 0.38); }
    .stage-row.muted   { opacity: 0.5; }

    .control-row {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
        margin-top: 14px;
    }

    button {
        min-height: 42px;
        border: 1px solid var(--border-strong);
        border-radius: 8px;
        background: #101820;
        color: var(--fg-base);
        font: 700 0.82rem var(--font-mono);
        cursor: pointer;
    }

    button:hover { border-color: var(--accent-cyan); color: #ffffff; }
    .btn-danger { border-color: rgba(255,51,51,0.4); }
    .btn-danger:hover { border-color: #ff3333; }

    /* Watched surfaces */
    .surface-band {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        padding: 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: rgba(12, 18, 23, 0.72);
    }

    .surface-chip {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 8px 10px;
        border: 1px solid var(--border);
        border-radius: 6px;
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.76rem;
        background: rgba(255, 255, 255, 0.025);
        transition: border-color 0.3s, color 0.3s;
    }

    .surface-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
        flex-shrink: 0;
    }

    .surface-active  { color: var(--accent-cyan); border-color: rgba(39, 215, 196, 0.35); }
    .surface-idle    { color: #f2b84b; border-color: rgba(242, 184, 75, 0.3); }
    .surface-offline { color: var(--fg-muted); opacity: 0.55; }

    /* Modal */
    .modal-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.55);
        z-index: 200;
        display: grid;
        place-items: center;
        border: none;
        padding: 0;
        cursor: default;
    }

    .modal-box {
        width: min(420px, 90vw);
        background: #0d1820;
        border: 1px solid var(--border);
        border-radius: 10px;
        box-shadow: 0 24px 64px rgba(0,0,0,0.7);
        overflow: hidden;
    }

    .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 18px;
        border-bottom: 1px solid var(--border);
        font-family: var(--font-mono);
        font-size: 0.9rem;
        font-weight: 700;
    }

    .modal-close {
        background: transparent;
        border: none;
        color: var(--fg-muted);
        font-size: 0.85rem;
        cursor: pointer;
        min-height: unset;
        padding: 4px 8px;
    }

    .modal-body {
        padding: 18px;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }

    .modal-label {
        font-family: var(--font-mono);
        font-size: 0.74rem;
        color: var(--fg-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .ip-grid {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }

    .ip-chip {
        padding: 6px 12px;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: rgba(0,0,0,0.3);
        color: var(--fg-base);
        font-family: var(--font-mono);
        font-size: 0.82rem;
        cursor: pointer;
        min-height: unset;
    }

    .ip-chip.selected {
        border-color: var(--accent-cyan);
        color: var(--accent-cyan);
        background: rgba(39, 215, 196, 0.08);
    }

    .modal-input {
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: rgba(0,0,0,0.35);
        color: var(--fg-base);
        font-family: var(--font-mono);
        font-size: 0.88rem;
        width: 100%;
        box-sizing: border-box;
    }

    .modal-input:focus {
        outline: none;
        border-color: var(--accent-cyan);
    }

    .modal-hint {
        margin: 0;
        font-size: 0.82rem;
        color: var(--fg-muted);
    }

    .modal-success {
        padding: 10px 12px;
        border-radius: 6px;
        background: rgba(183, 226, 107, 0.1);
        border: 1px solid rgba(183, 226, 107, 0.3);
        color: #b7e26b;
        font-family: var(--font-mono);
        font-size: 0.82rem;
    }

    .nft-block {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 12px;
        border: 1px solid rgba(242, 184, 75, 0.3);
        border-radius: 6px;
        background: rgba(242, 184, 75, 0.06);
    }

    .nft-label {
        font-family: var(--font-mono);
        font-size: 0.72rem;
        color: #f2b84b;
    }

    .nft-cmd {
        font-family: var(--font-mono);
        font-size: 0.78rem;
        color: var(--fg-base);
        word-break: break-all;
        line-height: 1.5;
    }

    .nft-copy-btn {
        align-self: flex-start;
        padding: 5px 12px;
        min-height: unset;
        font-size: 0.76rem;
        border: 1px solid rgba(242, 184, 75, 0.4);
        color: #f2b84b;
        background: transparent;
    }

    .modal-footer {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        padding: 14px 18px;
        border-top: 1px solid var(--border);
    }

    .modal-action {
        min-height: 40px;
        font-size: 0.8rem;
    }

    .modal-action.secondary { background: transparent; }
    .modal-action:disabled  { opacity: 0.4; cursor: not-allowed; }

    /* scrollbar */
    .event-list::-webkit-scrollbar { width: 8px; }
    .event-list::-webkit-scrollbar-track { background: rgba(255,255,255,0.03); }
    .event-list::-webkit-scrollbar-thumb { background: rgba(166,180,187,0.24); border-radius: 8px; }

    @media (max-width: 1060px) {
        .dashboard-grid { grid-template-columns: 1fr; }
        .side-stack { grid-template-rows: auto; }
    }

    @media (max-width: 760px) {
        .command-shell { width: min(100vw - 20px, 1480px); padding-top: 10px; }
        .command-header { min-height: auto; flex-direction: column; }
        .metric-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .feed-panel { min-height: auto; }
        .event-list { max-height: none; }
    }

    @media (max-width: 460px) {
        .metric-strip, .control-row { grid-template-columns: 1fr; }
    }
</style>
