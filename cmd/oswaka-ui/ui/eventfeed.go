//go:build fyne

package ui

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const maxFeedEvents = 200

// EventFeed is a scrollable list of live SIEM events with semantic colour coding.
type EventFeed struct {
	widget.BaseWidget
	events []Event
	list   *widget.List
}

func NewEventFeed() *EventFeed {
	f := &EventFeed{}
	f.list = widget.NewList(
		func() int { return len(f.events) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				canvas.NewRectangle(color.Transparent), // colour strip
				widget.NewLabel(""),                    // type badge
				widget.NewLabel(""),                    // summary
				widget.NewLabel(""),                    // timestamp
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id >= len(f.events) {
				return
			}
			ev := f.events[id]
			row := obj.(*fyne.Container)

			strip := row.Objects[0].(*canvas.Rectangle)
			strip.FillColor = eventColor(ev.Type)
			strip.SetMinSize(fyne.NewSize(4, 36))

			badge := row.Objects[1].(*widget.Label)
			badge.SetText(ev.Type)
			badge.TextStyle = fyne.TextStyle{Monospace: true}

			summary := row.Objects[2].(*widget.Label)
			summary.SetText(eventSummary(ev))

			ts := row.Objects[3].(*widget.Label)
			ts.SetText(ev.Timestamp.Format("15:04:05"))
			ts.Alignment = fyne.TextAlignTrailing
		},
	)
	f.ExtendBaseWidget(f)
	return f
}

// Push adds a new event to the top of the feed (thread-safe via Fyne main goroutine).
func (f *EventFeed) Push(ev Event) {
	f.events = append([]Event{ev}, f.events...)
	if len(f.events) > maxFeedEvents {
		f.events = f.events[:maxFeedEvents]
	}
	f.list.Refresh()
}

func (f *EventFeed) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(f.list)
}

func (f *EventFeed) MinSize() fyne.Size {
	return fyne.NewSize(360, 400)
}

// eventColor returns the semantic colour for an event type.
func eventColor(t string) color.Color {
	switch strings.ToUpper(t) {
	case "THREAT_ALERT":
		return color.NRGBA{R: 255, G: 51, B: 51, A: 200}
	case "PORT_SCAN":
		return color.NRGBA{R: 255, G: 153, B: 0, A: 200}
	case "DNS":
		return color.NRGBA{R: 0, G: 255, B: 255, A: 160}
	case "ARP":
		return color.NRGBA{R: 51, G: 255, B: 51, A: 160}
	case "TOR":
		return color.NRGBA{R: 154, G: 124, B: 255, A: 200}
	case "CANARY":
		return color.NRGBA{R: 242, G: 184, B: 75, A: 200}
	case "VM":
		return color.NRGBA{R: 183, G: 226, B: 107, A: 160}
	case "PROXY":
		return color.NRGBA{R: 111, G: 127, B: 135, A: 160}
	default:
		return theme.DisabledColor()
	}
}

func eventSummary(ev Event) string {
	if ev.Metadata != nil {
		// Kill chain
		if tactic, ok := ev.Metadata["mitre_tactic"].(string); ok {
			rule, _ := ev.Metadata["rule"].(string)
			return fmt.Sprintf("⛓ %s  [%s]", rule, tactic)
		}
		if rule, ok := ev.Metadata["rule"].(string); ok {
			return rule
		}
		if domain, ok := ev.Metadata["domain"].(string); ok {
			return domain
		}
	}
	if ev.Source != "" {
		return ev.Source
	}
	return fmt.Sprintf("event %s", time.Since(ev.Timestamp).Round(time.Second))
}
