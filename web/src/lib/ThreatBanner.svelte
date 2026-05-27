<script lang="ts">
    import { networkEvents } from '$lib/websocket';
    import { slide } from 'svelte/transition';
    
    let activeAlert = $state<any>(null);
    let timeout: ReturnType<typeof setTimeout>;

    $effect(() => {
        const latest = $networkEvents[0];
        if (latest && latest.type === 'THREAT_ALERT') {
            activeAlert = latest;
            if (timeout) clearTimeout(timeout);
            timeout = setTimeout(() => {
                activeAlert = null; // Auto-dismiss after 6s
            }, 6000);
        }
    });

    function dismiss() {
        activeAlert = null;
        if (timeout) clearTimeout(timeout);
    }
</script>

{#if activeAlert}
<div class="threat-banner" transition:slide={{duration: 400}}>
    <div class="threat-content">
        <span class="icon" aria-hidden="true">!</span>
        <div class="message">
            <strong>Critical threat detected</strong>
            <p>{activeAlert.metadata?.reason || 'Unknown anomaly detected'}</p>
            <p class="target">Target: {activeAlert.metadata?.target || 'Unknown'}</p>
        </div>
    </div>
    <button class="dismiss" onclick={dismiss} aria-label="Dismiss alert">X</button>
</div>
{/if}

<style>
    .threat-banner {
        position: fixed;
        bottom: 2rem;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        background: rgba(84, 18, 24, 0.96);
        border: 1px solid rgba(243, 91, 91, 0.58);
        border-radius: 8px;
        padding: 1rem 1.25rem;
        color: white;
        box-shadow: 0 18px 48px rgba(0, 0, 0, 0.38);
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 90%;
        max-width: 700px;
    }
    .threat-content {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .icon {
        width: 42px;
        height: 42px;
        display: grid;
        place-items: center;
        border: 1px solid rgba(255,255,255,0.36);
        border-radius: 8px;
        font-family: var(--font-mono);
        font-size: 1.45rem;
        font-weight: 700;
        animation: pulseFade 1.5s infinite;
    }
    .message strong {
        font-size: 1rem;
        letter-spacing: 0;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
        display: block;
    }
    .message p {
        margin: 0;
        font-size: 0.95rem;
        opacity: 0.95;
    }
    .target {
        font-family: var(--font-mono);
        font-size: 0.9rem !important;
        background: rgba(0,0,0,0.3);
        padding: 0.3rem 0.6rem;
        border-radius: 6px;
        margin-top: 0.6rem !important;
        display: inline-block;
        border: 1px solid rgba(255,255,255,0.2);
    }
    .dismiss {
        width: 36px;
        height: 36px;
        background: rgba(0, 0, 0, 0.22);
        border: 1px solid rgba(255, 255, 255, 0.24);
        border-radius: 8px;
        color: white;
        font-family: var(--font-mono);
        font-size: 0.9rem;
        font-weight: 700;
        cursor: pointer;
        transition: border-color 0.2s, background 0.2s;
    }
    .dismiss:hover {
        background: rgba(0, 0, 0, 0.34);
        border-color: rgba(255, 255, 255, 0.44);
    }
    
    @keyframes pulseFade {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
    }

    @media (max-width: 640px) {
        .threat-banner {
            bottom: 1rem;
            align-items: flex-start;
        }

        .threat-content {
            align-items: flex-start;
        }
    }
</style>
