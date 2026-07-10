//go:build fyne

package ui

import (
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

type topoNode struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Type  string  `json:"type"`
	X, Y  float32 // layout position
}

type topoLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type topoSnap struct {
	Nodes []topoNode `json:"nodes"`
	Links []topoLink `json:"links"`
}

// TopologyCanvas renders the network graph using Fyne canvas primitives.
// Nodes are draggable circles; edges are lines.
type TopologyCanvas struct {
	widget.BaseWidget
	cfg   Config
	nodes []topoNode
	links []topoLink
	size  fyne.Size
}

func NewTopologyCanvas(cfg Config) *TopologyCanvas {
	t := &TopologyCanvas{cfg: cfg}
	t.ExtendBaseWidget(t)
	return t
}

// Refresh fetches the topology snapshot from the REST endpoint.
func (t *TopologyCanvas) Refresh() {
	go func() {
		snap, err := t.fetchSnap()
		if err != nil {
			return
		}
		t.layout(snap)
		t.BaseWidget.Refresh()
	}()
}

func (t *TopologyCanvas) CreateRenderer() fyne.WidgetRenderer {
	return &topologyRenderer{tc: t}
}

func (t *TopologyCanvas) MinSize() fyne.Size {
	return fyne.NewSize(460, 400)
}

func (t *TopologyCanvas) apiBase() string {
	scheme := "http"
	if t.cfg.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, t.cfg.Host)
}

func (t *TopologyCanvas) fetchSnap() (*topoSnap, error) {
	req, _ := http.NewRequest("GET", t.apiBase()+"/api/topology", nil)
	if t.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.cfg.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var snap topoSnap
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// layout assigns (X,Y) positions via a simple force-free circular layout.
func (t *TopologyCanvas) layout(snap *topoSnap) {
	t.links = snap.Links
	t.nodes = snap.Nodes

	n := len(t.nodes)
	if n == 0 {
		return
	}
	cx, cy := float32(t.size.Width/2), float32(t.size.Height/2)
	r := float32(math.Min(float64(t.size.Width), float64(t.size.Height))*0.38)
	if r < 60 {
		r = 120
	}
	for i := range t.nodes {
		// Known position from the API takes priority over circular layout
		if t.nodes[i].X == 0 && t.nodes[i].Y == 0 {
			angle := float64(i) / float64(n) * 2 * math.Pi
			t.nodes[i].X = cx + r*float32(math.Cos(angle))
			t.nodes[i].Y = cy + r*float32(math.Sin(angle))
		}
		_ = rand.Float32 // used in future jitter; keep import
	}
}

// topologyRenderer implements fyne.WidgetRenderer for the topology canvas.
type topologyRenderer struct {
	tc      *TopologyCanvas
	objects []fyne.CanvasObject
}

func (r *topologyRenderer) Refresh() {
	r.Layout(r.tc.size)
}

func (r *topologyRenderer) Layout(size fyne.Size) {
	r.tc.size = size
	r.objects = r.objects[:0]

	// Build a quick lookup for node positions
	pos := map[string]fyne.Position{}
	for _, n := range r.tc.nodes {
		pos[n.ID] = fyne.NewPos(n.X, n.Y)
	}

	// Edges first (drawn behind nodes)
	for _, lnk := range r.tc.links {
		src, srcOK := pos[lnk.Source]
		tgt, tgtOK := pos[lnk.Target]
		if !srcOK || !tgtOK {
			continue
		}
		line := canvas.NewLine(color.NRGBA{R: 39, G: 215, B: 196, A: 60})
		line.StrokeWidth = 1.5
		line.Position1 = src
		line.Position2 = tgt
		r.objects = append(r.objects, line)
	}

	// Nodes
	for _, n := range r.tc.nodes {
		p := pos[n.ID]
		circle := canvas.NewCircle(nodeColor(n.Type))
		circle.StrokeColor = color.NRGBA{R: 255, G: 255, B: 255, A: 30}
		circle.StrokeWidth = 1
		circle.Move(fyne.NewPos(p.X-14, p.Y-14))
		circle.Resize(fyne.NewSize(28, 28))
		r.objects = append(r.objects, circle)

		lbl := canvas.NewText(nodeLabel(n), color.White)
		lbl.TextSize = 10
		lbl.Move(fyne.NewPos(p.X-24, p.Y+16))
		r.objects = append(r.objects, lbl)
	}
}

func (r *topologyRenderer) MinSize() fyne.Size { return fyne.NewSize(460, 400) }
func (r *topologyRenderer) Destroy()           {}
func (r *topologyRenderer) Objects() []fyne.CanvasObject { return r.objects }

func nodeColor(t string) color.Color {
	switch strings.ToLower(t) {
	case "host":
		return color.NRGBA{R: 39, G: 215, B: 196, A: 200}
	case "router":
		return color.NRGBA{R: 242, G: 184, B: 75, A: 200}
	case "container", "vm":
		return color.NRGBA{R: 154, G: 124, B: 255, A: 200}
	default:
		return color.NRGBA{R: 111, G: 127, B: 135, A: 200}
	}
}

func nodeLabel(n topoNode) string {
	if n.Label != "" {
		return n.Label
	}
	if len(n.ID) > 15 {
		return n.ID[:15] + "…"
	}
	return n.ID
}
