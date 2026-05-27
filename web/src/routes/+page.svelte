<script lang="ts">
    import { networkEvents, isConnected } from '$lib/websocket';
    import { fade, slide } from 'svelte/transition';
    import ThreatBanner from '$lib/ThreatBanner.svelte';
    import TopologyGraph from '$lib/TopologyGraph.svelte';

    const responseStages = [
        { label: 'Triage', value: '04 open', state: 'active' },
        { label: 'Containment', value: '02 queued', state: 'warning' },
        { label: 'Collection', value: '18 artifacts', state: 'calm' },
        { label: 'Recovery', value: '01 pending', state: 'muted' },
    ];

    const watchedSurfaces = ['DNS', 'ARP', 'Proxy DPI', 'VM inventory', 'Firefox profile', 'Backup chain'];

    let visibleEvents = $derived($networkEvents.slice(0, 14));
    let threatCount = $derived($networkEvents.filter((event) => event.type === 'THREAT_ALERT').length);
    let uniqueSources = $derived(new Set($networkEvents.map((event) => event.source || event.metadata?.source).filter(Boolean)).size);
    let latestEvent = $derived($networkEvents[0]);

    function getEventColor(type: string) {
        switch(type) {
            case 'THREAT_ALERT': return '#ff3333';
            case 'PORT_SCAN': return '#ff9900';
            case 'DNS': return '#00ffff';
            case 'ARP': return '#33ff33';
            default: return '#cccccc';
        }
    }

    function getEventBackground(type: string) {
        if(type === 'THREAT_ALERT') return 'rgba(255, 51, 51, 0.15)';
        return 'rgba(0,0,0,0.5)';
    }

    function getEventClass(type = '') {
        if (type === 'THREAT_ALERT') return 'critical';
        if (type === 'PORT_SCAN') return 'warning';
        if (type === 'DNS') return 'info';
        if (type === 'ARP') return 'good';
        return 'neutral';
    }

    function eventKey(event: any, index: number) {
        return event.id || `${event.type || 'event'}-${event.timestamp || 'pending'}-${index}`;
    }

    function formatTime(value: string | number | undefined) {
        return new Date(value || Date.now()).toLocaleTimeString();
    }
</script>

<svelte:head>
    <title>O.W.A.S.A.K.A. Command Center</title>
</svelte:head>

<ThreatBanner />

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
            <strong>{threatCount}</strong>
            <small>threat alerts</small>
        </article>
        <article>
            <span>Sources</span>
            <strong>{uniqueSources}</strong>
            <small>reporting nodes</small>
        </article>
        <article>
            <span>Last Signal</span>
            <strong>{latestEvent ? formatTime(latestEvent.timestamp) : '--:--:--'}</strong>
            <small>{latestEvent?.type || 'standby'}</small>
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
                    <article class="event-card {getEventClass(event.type)} animate-enter" style="--event-color: {getEventColor(event.type)}; --event-bg: {getEventBackground(event.type)}" transition:slide>
                        <div class="event-header">
                            <span>{event.type || 'SYSTEM'}</span>
                            <time>{formatTime(event.timestamp)}</time>
                        </div>
                        <pre>{JSON.stringify(event.metadata || event, null, 2)}</pre>
                    </article>
                {/each}

                {#if visibleEvents.length === 0}
                    <div class="empty-state" transition:fade>
                        <strong>No telemetry received</strong>
                        <span>Core stream is waiting on <code>ws://127.0.0.1:8080/ws</code>.</span>
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
                    <button type="button">Seal Host</button>
                    <button type="button">Export Case</button>
                </div>
            </section>
        </aside>
    </section>

    <section class="surface-band" aria-label="Watched surfaces">
        {#each watchedSurfaces as surface}
            <span>{surface}</span>
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

    .title-block {
        max-width: 760px;
    }

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

    .metric-strip span,
    .metric-strip small {
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

    .dashboard-grid {
        display: grid;
        grid-template-columns: minmax(0, 1.5fr) minmax(360px, 0.8fr);
        gap: 20px;
        align-items: stretch;
    }

    .panel {
        padding: 16px;
    }

    .panel-heading {
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: flex-start;
        margin-bottom: 14px;
    }

    h2 {
        margin: 0;
        font-size: 1.05rem;
    }

    .feed-count {
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.78rem;
    }

    .feed-panel {
        min-height: 680px;
    }

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
    }

    .event-card:hover {
        border-color: color-mix(in srgb, var(--event-color) 58%, var(--border));
        transform: translateY(-1px);
    }

    .event-header {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 8px;
        font-family: var(--font-mono);
        font-size: 0.78rem;
        font-weight: 700;
    }

    .event-header span {
        color: var(--event-color);
        overflow-wrap: anywhere;
    }

    .event-header time {
        color: var(--fg-muted);
        white-space: nowrap;
    }

    pre {
        margin: 0;
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.76rem;
        line-height: 1.5;
        overflow-x: auto;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
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

    .empty-state strong {
        color: var(--fg-base);
    }

    .empty-state code {
        color: var(--accent-cyan);
        font-family: var(--font-mono);
    }

    .side-stack {
        display: grid;
        gap: 20px;
        grid-template-rows: minmax(420px, 1fr) auto;
    }

    .topology-panel {
        min-height: 460px;
    }

    .response-panel {
        min-height: 250px;
    }

    .stage-list {
        display: grid;
        gap: 8px;
    }

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

    .stage-row strong {
        color: var(--fg-base);
    }

    .stage-row.active {
        border-color: rgba(39, 215, 196, 0.45);
    }

    .stage-row.warning {
        border-color: rgba(242, 184, 75, 0.48);
    }

    .stage-row.calm {
        border-color: rgba(183, 226, 107, 0.38);
    }

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

    button:hover {
        border-color: var(--accent-cyan);
        color: #ffffff;
    }

    .surface-band {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        padding: 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: rgba(12, 18, 23, 0.72);
    }

    .surface-band span {
        padding: 8px 10px;
        border: 1px solid var(--border);
        border-radius: 6px;
        color: var(--fg-muted);
        font-family: var(--font-mono);
        font-size: 0.76rem;
        background: rgba(255, 255, 255, 0.025);
    }

    .event-list::-webkit-scrollbar {
        width: 8px;
    }

    .event-list::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.03);
    }

    .event-list::-webkit-scrollbar-thumb {
        background: rgba(166, 180, 187, 0.24);
        border-radius: 8px;
    }

    @media (max-width: 1060px) {
        .dashboard-grid {
            grid-template-columns: 1fr;
        }

        .side-stack {
            grid-template-rows: auto;
        }
    }

    @media (max-width: 760px) {
        .command-shell {
            width: min(100vw - 20px, 1480px);
            padding-top: 10px;
        }

        .command-header {
            min-height: auto;
            flex-direction: column;
        }

        .metric-strip {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .feed-panel {
            min-height: auto;
        }

        .event-list {
            max-height: none;
        }
    }

    @media (max-width: 460px) {
        .metric-strip,
        .control-row {
            grid-template-columns: 1fr;
        }
    }
</style>
