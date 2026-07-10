<script lang="ts">
    import { fly } from 'svelte/transition';
    import { cubicOut } from 'svelte/easing';

    let { event, onclose }: { event: any; onclose: () => void } = $props();

    const SEVERITY_COLOR: Record<string, string> = {
        CRITICAL: '#ff3333',
        HIGH:     '#ff9900',
        MEDIUM:   '#f2b84b',
        LOW:      '#b7e26b',
        INFO:     '#27d7c4',
    };

    const TYPE_COLOR: Record<string, string> = {
        THREAT_ALERT: '#ff3333',
        PORT_SCAN:    '#ff9900',
        DNS:          '#00ffff',
        ARP:          '#33ff33',
        TOR:          '#9a7cff',
        CANARY:       '#f2b84b',
        VM:           '#b7e26b',
        PROXY:        '#6f7f87',
        PHYSICAL:     '#a6b4bb',
    };

    function color(event: any) {
        return TYPE_COLOR[event?.type] ?? '#cccccc';
    }

    function severityColor(sev: string) {
        return SEVERITY_COLOR[sev?.toUpperCase()] ?? '#cccccc';
    }

    function fmt(ts: string | number | undefined) {
        return new Date(ts || Date.now()).toLocaleString();
    }

    function copyJson() {
        navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    }

    function copyId() {
        if (event?.id) navigator.clipboard.writeText(event.id);
    }

    function handleKeydown(e: KeyboardEvent) {
        if (e.key === 'Escape') onclose();
    }

    const isKillChain = $derived(!!event?.metadata?.mitre_tactic);
    const severity = $derived(event?.metadata?.severity as string | undefined);
    const rule = $derived(event?.metadata?.rule as string | undefined);
    const chainEvents = $derived((event?.metadata?.chain_events as string[] | undefined) ?? []);
    const entropy = $derived(event?.metadata?.entropy as number | undefined);
    const vowelRatio = $derived(event?.metadata?.vowel_ratio as number | undefined);
    const mitreTactic = $derived(event?.metadata?.mitre_tactic as string | undefined);
    const otherMeta = $derived(
        Object.fromEntries(
            Object.entries(event?.metadata ?? {}).filter(([k]) =>
                !['severity','rule','description','trigger_id','mitre_tactic',
                  'chain_events','entropy','vowel_ratio','window'].includes(k)
            )
        )
    );
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- Backdrop -->
<button
    class="drawer-backdrop"
    onclick={onclose}
    aria-label="Close detail panel"
></button>

<!-- Drawer -->
<div
    class="event-drawer"
    transition:fly={{ x: 420, duration: 260, easing: cubicOut }}
    role="dialog"
    aria-modal="true"
    aria-label="Event detail"
>
    <div class="drawer-header" style="--ev-color: {color(event)}">
        <div class="drawer-type">{event?.type ?? 'EVENT'}</div>
        {#if severity}
            <span class="sev-badge" style="color: {severityColor(severity)}; border-color: {severityColor(severity)}44">
                {severity}
            </span>
        {/if}
        <button class="close-btn" onclick={onclose} aria-label="Close">✕</button>
    </div>

    <div class="drawer-body">
        <!-- Kill chain highlight -->
        {#if isKillChain}
            <section class="chain-block">
                <div class="chain-label">⛓️ Kill Chain Detected</div>
                {#if rule}<div class="chain-rule">{rule}</div>{/if}
                {#if mitreTactic}
                    <a
                        class="mitre-badge"
                        href="https://attack.mitre.org/tactics/{mitreTactic}/"
                        target="_blank"
                        rel="noopener noreferrer"
                    >{mitreTactic}</a>
                {/if}
                {#if chainEvents.length > 0}
                    <div class="chain-events">
                        {#each chainEvents as id}
                            <span class="chain-pill">{id.slice(0,8)}…</span>
                        {/each}
                    </div>
                {/if}
            </section>
        {:else if rule}
            <section class="rule-block">
                <span class="rule-label">Rule</span>
                <span class="rule-name">{rule}</span>
                {#if event?.metadata?.description}
                    <p class="rule-desc">{event.metadata.description}</p>
                {/if}
            </section>
        {/if}

        <!-- DGA metrics -->
        {#if entropy !== undefined}
            <section class="metrics-row">
                <div class="metric-item">
                    <span>Shannon entropy</span>
                    <strong style="color: {entropy > 3.8 ? '#ff9900' : '#27d7c4'}">{entropy.toFixed(3)}</strong>
                </div>
                {#if vowelRatio !== undefined}
                    <div class="metric-item">
                        <span>Vowel ratio</span>
                        <strong style="color: {vowelRatio < 0.38 ? '#ff9900' : '#27d7c4'}">{(vowelRatio * 100).toFixed(1)}%</strong>
                    </div>
                {/if}
            </section>
        {/if}

        <!-- Core fields -->
        <section class="fields-block">
            <div class="field-row">
                <span>ID</span>
                <button onclick={copyId} title="Click to copy" class="copy-id-btn">{event?.id ?? '—'}</button>
            </div>
            <div class="field-row">
                <span>Source</span>
                <code>{event?.source ?? '—'}</code>
            </div>
            {#if event?.destination}
                <div class="field-row">
                    <span>Destination</span>
                    <code>{event.destination}</code>
                </div>
            {/if}
            <div class="field-row">
                <span>Timestamp</span>
                <code>{fmt(event?.timestamp)}</code>
            </div>
        </section>

        <!-- Remaining metadata -->
        {#if Object.keys(otherMeta).length > 0}
            <section class="meta-block">
                <div class="meta-title">Metadata</div>
                {#each Object.entries(otherMeta) as [k, v]}
                    <div class="field-row">
                        <span>{k}</span>
                        <code>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</code>
                    </div>
                {/each}
            </section>
        {/if}
    </div>

    <div class="drawer-footer">
        <button onclick={copyJson} class="action-btn">Copy JSON</button>
        <button onclick={onclose} class="action-btn secondary">Close</button>
    </div>
</div>

<style>
    .drawer-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.45);
        z-index: 100;
        border: none;
        cursor: default;
        padding: 0;
    }

    .copy-id-btn {
        font-family: var(--font-mono);
        font-size: 0.78rem;
        color: var(--accent-cyan);
        background: transparent;
        border: none;
        padding: 0;
        cursor: pointer;
        overflow-wrap: anywhere;
        word-break: break-all;
        text-align: left;
    }

    .copy-id-btn:hover { text-decoration: underline; }

    .event-drawer {
        position: fixed;
        top: 0;
        right: 0;
        bottom: 0;
        width: min(420px, 92vw);
        background: #0d1820;
        border-left: 1px solid var(--border);
        box-shadow: -8px 0 32px rgba(0, 0, 0, 0.6);
        z-index: 101;
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }

    .drawer-header {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 16px 18px;
        border-bottom: 1px solid var(--border);
        background: linear-gradient(90deg, color-mix(in srgb, var(--ev-color) 12%, transparent), transparent);
    }

    .drawer-type {
        flex: 1;
        font-family: var(--font-mono);
        font-size: 0.8rem;
        font-weight: 700;
        color: var(--ev-color);
        letter-spacing: 0.06em;
    }

    .sev-badge {
        padding: 3px 8px;
        border: 1px solid;
        border-radius: 4px;
        font-family: var(--font-mono);
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .close-btn {
        width: 28px;
        height: 28px;
        border: none;
        border-radius: 4px;
        background: transparent;
        color: var(--fg-muted);
        font-size: 0.85rem;
        cursor: pointer;
        display: grid;
        place-items: center;
    }

    .close-btn:hover { background: rgba(255,255,255,0.06); color: var(--fg-base); }

    .drawer-body {
        flex: 1;
        overflow-y: auto;
        padding: 16px 18px;
        display: flex;
        flex-direction: column;
        gap: 16px;
    }

    .chain-block {
        padding: 14px;
        border: 1px solid rgba(255, 51, 51, 0.35);
        border-radius: 8px;
        background: rgba(255, 51, 51, 0.08);
    }

    .chain-label {
        font-size: 0.78rem;
        font-weight: 700;
        color: #ff3333;
        margin-bottom: 6px;
        letter-spacing: 0.04em;
    }

    .chain-rule {
        font-family: var(--font-mono);
        font-size: 0.9rem;
        color: var(--fg-base);
        margin-bottom: 8px;
    }

    .mitre-badge {
        display: inline-block;
        padding: 3px 8px;
        border: 1px solid rgba(154, 124, 255, 0.5);
        border-radius: 4px;
        background: rgba(154, 124, 255, 0.12);
        color: #9a7cff;
        font-family: var(--font-mono);
        font-size: 0.72rem;
        font-weight: 700;
        text-decoration: none;
        margin-bottom: 10px;
    }

    .chain-events {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
    }

    .chain-pill {
        padding: 2px 7px;
        border: 1px solid rgba(39, 215, 196, 0.3);
        border-radius: 4px;
        color: var(--accent-cyan);
        font-family: var(--font-mono);
        font-size: 0.68rem;
    }

    .rule-block {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .rule-label {
        font-family: var(--font-mono);
        font-size: 0.7rem;
        color: var(--fg-muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }

    .rule-name {
        font-family: var(--font-mono);
        font-size: 0.95rem;
        color: var(--fg-base);
        font-weight: 700;
    }

    .rule-desc {
        margin: 4px 0 0;
        font-size: 0.82rem;
        color: var(--fg-muted);
        line-height: 1.5;
    }

    .metrics-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
    }

    .metric-item {
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: rgba(0,0,0,0.25);
        display: flex;
        flex-direction: column;
        gap: 4px;
    }

    .metric-item span {
        font-family: var(--font-mono);
        font-size: 0.68rem;
        color: var(--fg-muted);
    }

    .metric-item strong {
        font-family: var(--font-mono);
        font-size: 1.1rem;
    }

    .fields-block, .meta-block {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }

    .meta-title {
        font-family: var(--font-mono);
        font-size: 0.7rem;
        color: var(--fg-muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 2px;
    }

    .field-row {
        display: grid;
        grid-template-columns: 90px 1fr;
        gap: 8px;
        align-items: baseline;
    }

    .field-row span {
        font-family: var(--font-mono);
        font-size: 0.72rem;
        color: var(--fg-muted);
        text-align: right;
    }

    .field-row code {
        font-family: var(--font-mono);
        font-size: 0.78rem;
        color: var(--accent-cyan);
        overflow-wrap: anywhere;
        word-break: break-all;
    }

    .drawer-footer {
        padding: 14px 18px;
        border-top: 1px solid var(--border);
        display: flex;
        gap: 10px;
    }

    .action-btn {
        flex: 1;
        min-height: 38px;
        border: 1px solid var(--border-strong);
        border-radius: 6px;
        background: #101820;
        color: var(--fg-base);
        font: 700 0.8rem var(--font-mono);
        cursor: pointer;
    }

    .action-btn:hover { border-color: var(--accent-cyan); color: #fff; }
    .action-btn.secondary { background: transparent; }

    .drawer-body::-webkit-scrollbar { width: 6px; }
    .drawer-body::-webkit-scrollbar-track { background: transparent; }
    .drawer-body::-webkit-scrollbar-thumb { background: rgba(166,180,187,0.2); border-radius: 4px; }
</style>
