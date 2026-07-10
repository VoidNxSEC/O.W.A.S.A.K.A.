<script lang="ts">
    import '../app.css';
    import { onMount } from 'svelte';
    import { connectWS } from '$lib/websocket';

    let { children } = $props();

    onMount(() => {
        connectWS();
    });
</script>

<div class="app-layout">
    {@render children()}
</div>
