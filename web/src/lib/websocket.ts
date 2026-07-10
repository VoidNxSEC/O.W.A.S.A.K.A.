import { writable, derived } from 'svelte/store';

export const networkEvents = writable<any[]>([]);
export const isConnected = writable(false);

let ws: WebSocket | null = null;

function deriveUrls() {
    const apiHost = (import.meta as any).env?.VITE_API_HOST ?? window.location.host;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    return {
        ws: `${proto}://${apiHost}/ws`,
        api: `${window.location.protocol}//${apiHost}`,
    };
}

export function getApiBase(): string {
    return deriveUrls().api;
}

export function connectWS() {
    if (ws && ws.readyState !== WebSocket.CLOSED) return;

    const { ws: wsUrl } = deriveUrls();
    const token = sessionStorage.getItem('oswaka_token');
    const url = token ? `${wsUrl}?token=${encodeURIComponent(token)}` : wsUrl;

    ws = new WebSocket(url);

    ws.onopen = () => {
        console.log('🟢 Connected to O.W.A.S.A.K.A Core');
        isConnected.set(true);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            networkEvents.update(cur => [data, ...cur].slice(0, 500));
        } catch (e) {
            console.error('Failed to parse event', e);
        }
    };

    ws.onclose = () => {
        console.log('🔴 Disconnected from core, retrying...');
        isConnected.set(false);
        setTimeout(() => connectWS(), 2000);
    };
}

// Derived store: last-seen timestamp per event type (for watched surfaces)
export const lastSeenByType = derived(networkEvents, ($events) => {
    const map: Record<string, number> = {};
    for (const ev of $events) {
        const t = ev.type as string;
        if (t && !map[t]) {
            map[t] = new Date(ev.timestamp || Date.now()).getTime();
        }
    }
    return map;
});
