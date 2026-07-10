//go:build fyne

package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// Alert mirrors the Alert model returned by GET /api/alerts.
type Alert struct {
	ID          string `json:"id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Source      string `json:"source"`
	MitreTactic string `json:"mitre_tactic,omitempty"`
	Note        string `json:"note,omitempty"`
}

// AlertPanel shows the live alert list with TRIAGE / SEAL HOST buttons.
type AlertPanel struct {
	widget.BaseWidget
	cfg     Config
	window  fyne.Window
	alerts  []Alert
	list    *widget.List
	counts  *widget.Label
}

func NewAlertPanel(cfg Config, win fyne.Window) *AlertPanel {
	p := &AlertPanel{cfg: cfg, window: win}
	p.counts = widget.NewLabel("NEW: 0  TRIAGING: 0  CONTAINED: 0  CLOSED: 0")
	p.counts.TextStyle = fyne.TextStyle{Monospace: true}

	p.list = widget.NewList(
		func() int { return len(p.alerts) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel(""),         // severity
				widget.NewLabel(""),         // rule
				widget.NewLabel(""),         // source
				widget.NewLabel(""),         // status
				widget.NewButton("TRIAGE", nil),
				widget.NewButton("SEAL HOST", nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(p.alerts) {
				return
			}
			a := p.alerts[id]
			row := obj.(*fyne.Container)

			row.Objects[0].(*widget.Label).SetText(a.Severity)
			row.Objects[1].(*widget.Label).SetText(a.RuleName)
			row.Objects[2].(*widget.Label).SetText(a.Source)
			row.Objects[3].(*widget.Label).SetText(a.Status)

			triage := row.Objects[4].(*widget.Button)
			triage.OnTapped = func() { p.patch(a.ID, "TRIAGING", "") }

			seal := row.Objects[5].(*widget.Button)
			seal.OnTapped = func() { p.sealHost(a) }
		},
	)
	p.ExtendBaseWidget(p)
	return p
}

// Refresh fetches fresh alerts from the backend.
func (p *AlertPanel) Refresh() {
	go func() {
		alerts, err := p.fetchAlerts()
		if err != nil {
			return
		}
		p.alerts = alerts
		p.updateCounts()
		p.list.Refresh()
	}()
}

// OnAlertUpdate handles a WebSocket ALERT_UPDATE event (real-time refresh).
func (p *AlertPanel) OnAlertUpdate(_ Event) {
	p.Refresh()
}

func (p *AlertPanel) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(
		container.NewBorder(p.counts, nil, nil, nil, p.list),
	)
}

func (p *AlertPanel) MinSize() fyne.Size {
	return fyne.NewSize(720, 200)
}

func (p *AlertPanel) apiBase() string {
	scheme := "http"
	if p.cfg.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, p.cfg.Host)
}

func (p *AlertPanel) authHeader() http.Header {
	h := http.Header{}
	if p.cfg.Token != "" {
		h.Set("Authorization", "Bearer "+p.cfg.Token)
	}
	return h
}

func (p *AlertPanel) fetchAlerts() ([]Alert, error) {
	req, _ := http.NewRequest("GET", p.apiBase()+"/api/alerts?limit=100", nil)
	req.Header = p.authHeader()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var alerts []Alert
	json.Unmarshal(body, &alerts)
	return alerts, nil
}

func (p *AlertPanel) patch(id, status, note string) {
	body, _ := json.Marshal(map[string]string{"status": status, "note": note})
	req, _ := http.NewRequest("PATCH", p.apiBase()+"/api/alerts/"+id, bytes.NewReader(body))
	req.Header = p.authHeader()
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req) //nolint:errcheck
	p.Refresh()
}

func (p *AlertPanel) sealHost(a Alert) {
	ip := a.Source
	cmd := "nft add rule inet filter input ip saddr " + ip + " drop"

	// Try the API first
	body, _ := json.Marshal(map[string]string{"ip": ip})
	req, _ := http.NewRequest("POST", p.apiBase()+"/api/incidents/containment", bytes.NewReader(body))
	req.Header = p.authHeader()
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	apiOK := err == nil && resp.StatusCode < 300

	msg := fmt.Sprintf("Containment request sent for %s\n\nRun as root to apply immediately:\n\n%s", ip, cmd)
	if !apiOK {
		msg = fmt.Sprintf("API unreachable — run manually as root:\n\n%s", cmd)
	}

	dialog.ShowInformation("Seal Host — "+ip, msg, p.window)
}

func (p *AlertPanel) updateCounts() {
	counts := map[string]int{"NEW": 0, "TRIAGING": 0, "CONTAINED": 0, "CLOSED": 0}
	for _, a := range p.alerts {
		counts[strings.ToUpper(a.Status)]++
	}
	p.counts.SetText(fmt.Sprintf(
		"NEW: %d  TRIAGING: %d  CONTAINED: %d  CLOSED: %d",
		counts["NEW"], counts["TRIAGING"], counts["CONTAINED"], counts["CLOSED"],
	))
}
