<script lang="ts">
    import { onMount } from 'svelte';
    import { networkEvents, getApiBase } from '$lib/websocket';
    import * as d3 from 'd3';

    type TopologyNode = {
        id: string;
        label?: string;
        type?: string;
        x?: number;
        y?: number;
        fx?: number | null;
        fy?: number | null;
    };

    type TopologyLink = {
        source: string | TopologyNode;
        target: string | TopologyNode;
    };

    let svgContainer: HTMLElement;

    let nodes: TopologyNode[] = [];
    let links: TopologyLink[] = [];
    let simulation: d3.Simulation<TopologyNode, undefined>;

    const NODE_COLORS: Record<string, string> = {
        host:      '#27d7c4',
        router:    '#f2b84b',
        container: '#9a7cff',
        vm:        '#b7e26b',
        unknown:   '#6f7f87',
        THREAT:    '#f35b5b',
    };

    onMount(() => {
        const width = svgContainer.clientWidth;
        const height = svgContainer.clientHeight || 450;

        const svg = d3.select(svgContainer)
            .append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", `0 0 ${width} ${height}`);

        const g = svg.append("g");

        // Force simulation initialization
        simulation = d3.forceSimulation<TopologyNode>()
            .force("link", d3.forceLink().id((d: any) => d.id).distance(120))
            .force("charge", d3.forceManyBody().strength(-250))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(40));

        let linkSelection: any = g.append("g").attr("class", "links").selectAll(".link");
        let nodeSelection: any = g.append("g").attr("class", "nodes").selectAll(".node");

        // Load initial topology snapshot from REST
        fetch(`${getApiBase()}/api/topology`)
            .then((resp) => resp.ok ? resp.json() : null)
            .then((snap) => {
                if (!snap) return;
                nodes = (snap.nodes || []).map((n: TopologyNode) => ({...n}));
                links = (snap.links || []).map((l: TopologyLink) => ({...l}));
                updateGraph();
            })
            .catch(() => { /* backend not yet ready - wait for WS events */ });

        function updateGraph() {
            // Re-bind links
            linkSelection = linkSelection.data(links, (d: TopologyLink) => {
                const source = typeof d.source === 'string' ? d.source : d.source.id;
                const target = typeof d.target === 'string' ? d.target : d.target.id;
                return `${source}-${target}`;
            });
            linkSelection.exit().remove();
            const linkEnter = linkSelection.enter().append("line")
                .attr("class", "link")
                .style("stroke", "rgba(39, 215, 196, 0.22)")
                .style("stroke-width", 1.5);
            linkSelection = linkEnter.merge(linkSelection as any);

            // Re-bind nodes
            nodeSelection = nodeSelection.data(nodes, (d: TopologyNode) => d.id);
            nodeSelection.exit().remove();
            
            const nodeEnter = nodeSelection.enter().append("g")
                .attr("class", "node")
                .style("cursor", "grab")
                .call(d3.drag<SVGGElement, TopologyNode>()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            nodeEnter.append("circle")
                .attr("r", 10)
                .attr("fill", (d: any) => NODE_COLORS[d.type] ?? '#00ffd5')
                .attr("stroke", "rgba(231,238,242,0.24)")
                .attr("stroke-width", 2);

            nodeEnter.append("text")
                .attr("dx", 15)
                .attr("dy", ".35em")
                .text((d: TopologyNode) => d.id)
                .style("fill", "#e7eef2")
                .style("font-size", "11px")
                .style("font-family", "IBM Plex Mono, JetBrains Mono, ui-monospace, monospace");

            nodeSelection = nodeEnter.merge(nodeSelection as any);

            // Restart physics
            simulation.nodes(nodes);
            (simulation.force("link") as any).links(links);
            simulation.alpha(1).restart();
        }

        simulation.on("tick", () => {
            linkSelection
                .attr("x1", (d: any) => d.source.x)
                .attr("y1", (d: any) => d.source.y)
                .attr("x2", (d: any) => d.target.x)
                .attr("y2", (d: any) => d.target.y);

            nodeSelection.attr("transform", (d: TopologyNode) => `translate(${d.x},${d.y})`);
        });

        // Live stream bindings
        const unsubscribe = networkEvents.subscribe(events => {
            if (!events.length) return;
            const ev = events[0];

            // Full topology replacement from backend mapper
            if (ev.type === 'TOPOLOGY_UPDATE' && ev.data) {
                nodes = (ev.data.nodes || []).map((n: any) => ({...n}));
                links = (ev.data.links || []).map((l: any) => ({...l}));
                updateGraph();
                return;
            }

            // Incremental update from raw network events
            let sourceId = ev.source || "Unknown";
            let destId = ev.destination || "Broadcast";

            if (ev.type === 'THREAT_ALERT') destId = ev.metadata?.target || destId;

            const nodeType = ev.type === 'THREAT_ALERT' ? 'THREAT' : 'unknown';

            let sNode = nodes.find((n: TopologyNode) => n.id === sourceId);
            if (!sNode) {
                sNode = { id: sourceId, label: sourceId, type: nodeType };
                nodes.push(sNode);
            }
            if (ev.type === 'THREAT_ALERT') sNode.type = 'THREAT';

            let dNode = nodes.find((n: TopologyNode) => n.id === destId);
            if (!dNode) {
                dNode = { id: destId, label: destId, type: nodeType };
                nodes.push(dNode);
            }
            if (ev.type === 'THREAT_ALERT') dNode.type = 'THREAT';

            const existingLink = links.find((l: any) =>
                (l.source?.id === sourceId || l.source === sourceId) &&
                (l.target?.id === destId   || l.target === destId)
            );
            if (!existingLink && sourceId !== destId) {
                links.push({ source: sourceId, target: destId });
            }

            if (nodes.length > 40) {
                nodes = nodes.slice(-40);
                const validIds = new Set(nodes.map((n: TopologyNode) => n.id));
                links = links.filter((l: any) =>
                    validIds.has(l.source?.id ?? l.source) &&
                    validIds.has(l.target?.id ?? l.target)
                );
            }

            updateGraph();
        });

        // D3 Drag Event Handlers
        function dragstarted(this: SVGGElement, event: any, d: TopologyNode) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
            d3.select(this).style("cursor", "grabbing");
        }

        function dragged(event: any, d: TopologyNode) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(this: SVGGElement, event: any, d: TopologyNode) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
            d3.select(this).style("cursor", "grab");
        }

        return () => {
            unsubscribe();
            simulation.stop();
        };
    });
</script>

<div class="topology-container" bind:this={svgContainer}>
</div>

<style>
    .topology-container {
        width: 100%;
        height: 100%;
        min-height: 450px;
        position: relative;
        background:
            linear-gradient(rgba(255,255,255,0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px),
            rgba(0,0,0,0.14);
        background-size: 32px 32px;
        border: 1px solid var(--border);
        border-radius: 8px;
        overflow: hidden;
    }
</style>
