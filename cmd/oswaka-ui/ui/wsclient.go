//go:build fyne

package ui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// Event mirrors the wire format from the OWASAKA WebSocket stream.
type Event struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Source      string         `json:"source"`
	Destination string         `json:"destination"`
	Metadata    map[string]any `json:"metadata"`
	Timestamp   time.Time      `json:"timestamp"`
}

// WSClient maintains a persistent WebSocket connection to OWASAKA core
// and fans events out to registered listeners.
type WSClient struct {
	host      string
	token     string
	tls       bool
	listeners []func(Event)
	stop      chan struct{}
}

func NewWSClient(host, token string, tls bool) *WSClient {
	return &WSClient{host: host, token: token, tls: tls, stop: make(chan struct{})}
}

// Subscribe registers a callback that is called on each incoming event.
func (c *WSClient) Subscribe(fn func(Event)) {
	c.listeners = append(c.listeners, fn)
}

// Start connects and reads in a goroutine, reconnecting on disconnect.
func (c *WSClient) Start() {
	go c.loop()
}

// Stop closes the connection and halts the loop.
func (c *WSClient) Stop() {
	close(c.stop)
}

func (c *WSClient) loop() {
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		if err := c.connect(); err != nil {
			time.Sleep(2 * time.Second)
		}
	}
}

func (c *WSClient) connect() error {
	scheme := "ws"
	if c.tls {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: c.host, Path: "/ws"}
	if c.token != "" {
		q := u.Query()
		q.Set("token", c.token)
		u.RawQuery = q.Encode()
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}
	defer conn.Close()

	for {
		select {
		case <-c.stop:
			return nil
		default:
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var ev Event
		if json.Unmarshal(msg, &ev) == nil {
			for _, fn := range c.listeners {
				fn(ev)
			}
		}
	}
}
