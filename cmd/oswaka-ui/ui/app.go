//go:build fyne

// Package ui implements the O.W.A.S.A.K.A. native desktop UI using Fyne.
//
// Window layout:
//
//	┌─ O.W.A.S.A.K.A. ─────────────────────────────────────────────────────┐
//	│  ● host:port  │  events: N  │  alerts: N  │  kill chains: N  │ HH:MM │
//	├──────────────────────────┬────────────────────────────────────────────┤
//	│  LIVE FEED               │  NETWORK TOPOLOGY                          │
//	│  ⛓ RECON_TO_PORTSCAN    │  [Fyne canvas — circles + lines]           │
//	│    10.0.0.5 TA0043       │                                            │
//	│  ⚠ DGA_DOMAIN_DETECTED  │                                            │
//	│    10.0.0.5 HIGH         │                                            │
//	│  ● DNS  10.0.0.5         │                                            │
//	├──────────────────────────┴────────────────────────────────────────────┤
//	│  ALERTS  NEW:3  TRIAGING:1  CONTAINED:0  CLOSED:2                     │
//	│  RECON_TO_PORTSCAN  10.0.0.5  HIGH  NEW  [TRIAGE]  [SEAL HOST]        │
//	└───────────────────────────────────────────────────────────────────────┘
//
// ChainScope integration point (TODO — wire when ChainScope is ready):
//
//	NATS subject: chainscope.intel.v1
//	Handler:      internal/events/chainscope.go (not yet implemented)
//	UI panel:     add a "ChainScope Intel" tab to the bottom panel
package ui

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// Config is passed from main.go.
type Config struct {
	Host  string
	Token string
	TLS   bool
}

// MainWindow is the root Fyne window for the SIEM desktop UI.
type MainWindow struct {
	win      fyne.Window
	feed     *EventFeed
	topology *TopologyCanvas
	alerts   *AlertPanel
	status   *widget.Label
	counts   *widget.Label
	ws       *WSClient

	eventTotal int
	alertTotal int
	chainTotal int
}

// NewMainWindow constructs and returns the wired-up main window.
func NewMainWindow(a fyne.App, cfg Config) fyne.Window {
	win := a.NewWindow("O.W.A.S.A.K.A. — Command Center")
	win.SetMaster()
	win.Resize(fyne.NewSize(1280, 800))

	m := &MainWindow{
		win:      win,
		feed:     NewEventFeed(),
		topology: NewTopologyCanvas(cfg),
		alerts:   NewAlertPanel(cfg, win),
		status:   widget.NewLabel("● " + cfg.Host),
		counts:   widget.NewLabel("events: 0  alerts: 0  kill chains: 0"),
	}

	m.status.TextStyle = fyne.TextStyle{Monospace: true}
	m.counts.TextStyle = fyne.TextStyle{Monospace: true}

	// Status bar (top)
	clock := widget.NewLabel("")
	go func() {
		for {
			clock.SetText(time.Now().Format("15:04:05"))
			time.Sleep(time.Second)
		}
	}()
	statusBar := container.NewHBox(m.status, widget.NewSeparator(), m.counts, widget.NewSeparator(), clock)

	// Main split: feed left, topology right
	feedPanel := container.NewBorder(
		widget.NewLabel("LIVE FEED"),
		nil, nil, nil,
		m.feed,
	)
	topoPanel := container.NewBorder(
		widget.NewLabel("NETWORK TOPOLOGY"),
		nil, nil, nil,
		m.topology,
	)
	topSplit := container.NewHSplit(feedPanel, topoPanel)
	topSplit.SetOffset(0.38)

	// Bottom: alert panel
	alertsSection := container.NewBorder(
		widget.NewLabel("ALERTS"),
		nil, nil, nil,
		m.alerts,
	)

	// TODO: ChainScope Intel tab — add here when chainscope.go is implemented
	// bottomTabs := container.NewAppTabs(
	//     container.NewTabItem("Alerts",         alertsSection),
	//     container.NewTabItem("ChainScope Intel", newChainScopePanel(cfg, win)),
	// )

	mainSplit := container.NewVSplit(topSplit, alertsSection)
	mainSplit.SetOffset(0.65)

	win.SetContent(container.NewBorder(statusBar, nil, nil, nil, mainSplit))

	// Wire WebSocket
	m.ws = NewWSClient(cfg.Host, cfg.Token, cfg.TLS)
	m.ws.Subscribe(func(ev Event) {
		fyne.Do(func() {
			m.eventTotal++
			if ev.Type == "THREAT_ALERT" {
				m.alertTotal++
			}
			if ev.Metadata != nil {
				if _, ok := ev.Metadata["mitre_tactic"]; ok {
					m.chainTotal++
				}
			}
			m.counts.SetText(fmt.Sprintf(
				"events: %d  alerts: %d  kill chains: %d",
				m.eventTotal, m.alertTotal, m.chainTotal,
			))
			m.feed.Push(ev)
			if ev.Type == "ALERT_UPDATE" {
				m.alerts.OnAlertUpdate(ev)
			}
			if ev.Type == "TOPOLOGY_UPDATE" {
				m.topology.Refresh()
			}
		})
	})
	m.ws.Start()

	// Initial topology + alert fetch
	m.topology.Refresh()
	m.alerts.Refresh()

	win.SetOnClosed(func() { m.ws.Stop() })

	return win
}
