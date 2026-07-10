// owasaka-notify: SwayNC/dunst notification daemon for O.W.A.S.A.K.A. SIEM.
//
// Watches the OWASAKA WebSocket and fires libnotify notifications for
// CRITICAL/HIGH alerts. SwayNC intercepts them automatically.
// Deduplicates by alert ID — each alert fires exactly once.
//
// Notification actions (via swaync or dunst):
//   TRIAGE  → PATCH /api/alerts/{id}  status=TRIAGING
//   DISMISS → no-op (notification closed)
//
// Usage:
//
//	owasaka-notify [--host localhost:8080] [--token TOKEN] [--tls]
//	owasaka-notify --test    (fire a sample notification and exit)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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

var (
	seen   = map[string]bool{}
	seenMu sync.Mutex
	host   string
	token  string
	tls    bool
)

func markSeen(id string) bool {
	seenMu.Lock()
	defer seenMu.Unlock()
	if seen[id] {
		return false
	}
	seen[id] = true
	return true
}

func notify(ev event) {
	if ev.Type != "THREAT_ALERT" {
		return
	}
	if !markSeen(ev.ID) {
		return
	}

	sev, _ := ev.Metadata["severity"].(string)
	rule, _ := ev.Metadata["rule"].(string)
	tactic, _ := ev.Metadata["mitre_tactic"].(string)

	sev = strings.ToUpper(sev)
	if sev != "CRITICAL" && sev != "HIGH" {
		return
	}

	urgency := "normal"
	if sev == "CRITICAL" {
		urgency = "critical"
	}

	title := fmt.Sprintf("⚠ %s", rule)
	if tactic != "" {
		title = fmt.Sprintf("⛓ %s  [%s]", rule, tactic)
	}

	body := fmt.Sprintf("Source: %s\nSeverity: %s", ev.Source, sev)
	if ev.Metadata["chain_events"] != nil {
		body += "\nKill chain sequence detected"
	}

	// Expiry: CRITICAL = no timeout (must dismiss), HIGH = 30s
	expireMs := "30000"
	if sev == "CRITICAL" {
		expireMs = "0"
	}

	args := []string{
		"--urgency=" + urgency,
		"--app-name=OWASAKA",
		"--category=security",
		"--expire-time=" + expireMs,
		"--icon=security-high",
		"--hint=string:x-dunst-stack-tag:owasaka-" + ev.ID,
		"--action=triage=Triage",
		"--action=dismiss=Dismiss",
		title,
		body,
	}

	out, err := exec.Command("notify-send", args...).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "notify-send error: %v — %s\n", err, out)
		return
	}

	// notify-send with --action prints the chosen action to stdout
	// (dunst / swaync with libnotify >= 0.7.10).
	// If the user clicked "Triage", patch the alert status.
	action := strings.TrimSpace(string(out))
	if action == "triage" {
		go patchAlert(ev.ID, "TRIAGING")
	}
}

func patchAlert(id, status string) {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	apiBase := fmt.Sprintf("%s://%s", scheme, host)
	body, _ := json.Marshal(map[string]string{"status": status})
	req, err := http.NewRequest("PATCH", apiBase+"/api/alerts/"+id, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	http.DefaultClient.Do(req) //nolint:errcheck
}

func connect() {
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
			fmt.Fprintf(os.Stderr, "owasaka-notify: reconnecting (%v)\n", err)
			time.Sleep(3 * time.Second)
			continue
		}

		fmt.Fprintf(os.Stderr, "owasaka-notify: connected to %s\n", host)

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				conn.Close()
				break
			}
			var ev event
			if json.Unmarshal(msg, &ev) == nil {
				go notify(ev)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func testNotify() {
	fake := event{
		ID:   "test-001",
		Type: "THREAT_ALERT",
		Source: "10.0.0.5",
		Metadata: map[string]any{
			"rule":         "RECON_TO_PORTSCAN",
			"severity":     "CRITICAL",
			"mitre_tactic": "TA0043",
		},
		Time: time.Now(),
	}
	// bypass dedup
	seenMu.Lock()
	delete(seen, fake.ID)
	seenMu.Unlock()
	notify(fake)
}

func main() {
	hostFlag := flag.String("host", envOr("OSWAKA_HOST", "localhost:8080"), "OWASAKA host:port")
	tokenFlag := flag.String("token", os.Getenv("OSWAKA_TOKEN"), "JWT bearer token")
	tlsFlag := flag.Bool("tls", false, "use wss/https")
	test := flag.Bool("test", false, "fire a sample CRITICAL alert and exit")
	flag.Parse()

	host = *hostFlag
	token = *tokenFlag
	tls = *tlsFlag

	if *test {
		testNotify()
		time.Sleep(300 * time.Millisecond) // let notify-send finish
		return
	}

	connect()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
