// owasaka-bar: Waybar custom module for O.W.A.S.A.K.A. SIEM.
//
// Connects to the OWASAKA WebSocket and writes a JSON line to stdout
// on every state change. Waybar reads each line and updates the module
// in real time (no polling interval needed — set "interval": 0).
//
// Usage:
//
//	owasaka-bar [--host localhost:8080] [--token TOKEN] [--tls]
//
// Waybar config (owasaka.jsonc):
//
//	"custom/owasaka": {
//	  "exec": "owasaka-bar --host localhost:8080",
//	  "return-type": "json",
//	  "interval": 0,
//	  "on-click": "xdg-open http://localhost:8080"
//	}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type event struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Source   string         `json:"source"`
	Metadata map[string]any `json:"metadata"`
	Time     time.Time      `json:"timestamp"`
}

// barOutput is the JSON Waybar reads from stdout.
type barOutput struct {
	Text       string `json:"text"`
	Alt        string `json:"alt"`
	Tooltip    string `json:"tooltip"`
	Class      string `json:"class"`
	Percentage int    `json:"percentage"`
}

type state struct {
	mu          sync.Mutex
	eventTotal  int
	alertTotal  int
	chainTotal  int
	critTotal   int
	recent      []string // last 8 event summaries for tooltip
	connected   bool
}

func (s *state) push(ev event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventTotal++
	t := strings.ToUpper(ev.Type)
	if t == "THREAT_ALERT" {
		s.alertTotal++
		if sev, _ := ev.Metadata["severity"].(string); strings.EqualFold(sev, "critical") {
			s.critTotal++
		}
	}
	if ev.Metadata != nil {
		if _, ok := ev.Metadata["mitre_tactic"]; ok {
			s.chainTotal++
		}
	}
	line := eventLine(ev)
	s.recent = append([]string{line}, s.recent...)
	if len(s.recent) > 8 {
		s.recent = s.recent[:8]
	}
}

func (s *state) snapshot() barOutput {
	s.mu.Lock()
	defer s.mu.Unlock()

	connIcon := "◉"
	if !s.connected {
		connIcon = "○"
	}

	text := fmt.Sprintf("%s %d  ⚠ %d  ⛓ %d", connIcon, s.eventTotal, s.alertTotal, s.chainTotal)

	// CSS class drives waybar animations
	class := "connected"
	if !s.connected {
		class = "disconnected"
	} else if s.critTotal > 0 {
		class = "critical"
	} else if s.alertTotal > 0 {
		class = "alert"
	}

	tooltip := "O.W.A.S.A.K.A. — no events yet"
	if len(s.recent) > 0 {
		tooltip = "Recent events:\n" + strings.Join(s.recent, "\n")
	}
	if !s.connected {
		tooltip = "Core offline — reconnecting…"
	}

	// percentage drives the waybar progress bar (unused visually but surfaced for scripts)
	pct := 0
	if s.connected {
		pct = 100
	}

	return barOutput{
		Text:       text,
		Alt:        class,
		Tooltip:    tooltip,
		Class:      class,
		Percentage: pct,
	}
}

func eventLine(ev event) string {
	prefix := "●"
	t := strings.ToUpper(ev.Type)
	switch t {
	case "THREAT_ALERT":
		prefix = "⚠"
		if tactic, ok := ev.Metadata["mitre_tactic"].(string); ok {
			rule, _ := ev.Metadata["rule"].(string)
			return fmt.Sprintf("⛓ %s  %s  [%s]", rule, ev.Source, tactic)
		}
		if rule, ok := ev.Metadata["rule"].(string); ok {
			return fmt.Sprintf("%s %s  %s", prefix, rule, ev.Source)
		}
	case "TOR":
		prefix = "⬡"
	case "CANARY":
		prefix = "◆"
	case "DNS":
		if domain, ok := ev.Metadata["domain"].(string); ok {
			return fmt.Sprintf("● DNS  %s", domain)
		}
	}
	src := ev.Source
	if src == "" {
		src = ev.Type
	}
	return fmt.Sprintf("%s %s  %s", prefix, t, src)
}

func emit(out barOutput) {
	b, _ := json.Marshal(out)
	fmt.Printf("%s\n", b)
}

func connect(host, token string, tls bool, st *state) {
	scheme := "ws"
	if tls {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: host, Path: "/ws"}
	if token != "" {
		q := u.Query()
		q.Set("token", token)
		u.RawQuery = q.Encode()
	}

	for {
		conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			st.mu.Lock()
			st.connected = false
			st.mu.Unlock()
			emit(st.snapshot())
			time.Sleep(3 * time.Second)
			continue
		}

		st.mu.Lock()
		st.connected = true
		st.mu.Unlock()
		emit(st.snapshot())

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				conn.Close()
				st.mu.Lock()
				st.connected = false
				st.mu.Unlock()
				emit(st.snapshot())
				break
			}
			var ev event
			if json.Unmarshal(msg, &ev) == nil {
				st.push(ev)
				emit(st.snapshot())
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func main() {
	host := flag.String("host", envOr("OSWAKA_HOST", "localhost:8080"), "OWASAKA host:port")
	token := flag.String("token", os.Getenv("OSWAKA_TOKEN"), "JWT bearer token")
	tls := flag.Bool("tls", false, "use wss/https")
	flag.Parse()

	st := &state{}

	// Emit "connecting" state immediately so waybar has something to show
	emit(st.snapshot())

	connect(*host, *token, *tls, st)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
