// Package main implements the O.W.A.S.A.K.A. native desktop UI (Fyne).
package main

// Config holds all CLI flags for the UI process.
// Parsed once in main and passed down to all UI components.
type Config struct {
	Host  string // host:port of the OWASAKA backend (e.g. "localhost:8080")
	Token string // JWT bearer token (reads sessionStorage equivalent for a native app)
	TLS   bool   // use wss/https instead of ws/http
}
