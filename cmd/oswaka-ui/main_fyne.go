//go:build fyne

package main

import (
	"flag"
	"fmt"
	"os"

	"fyne.io/fyne/v2/app"

	fyneui "github.com/marcosfpina/O.W.A.S.A.K.A/cmd/oswaka-ui/ui"
)

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Host, "host", envOr("OSWAKA_HOST", "localhost:8080"), "OWASAKA backend host:port")
	flag.StringVar(&cfg.Token, "token", os.Getenv("OSWAKA_TOKEN"), "JWT bearer token")
	flag.BoolVar(&cfg.TLS, "tls", false, "use wss/https")
	flag.Parse()

	if cfg.Host == "" {
		fmt.Fprintln(os.Stderr, "error: --host is required")
		os.Exit(1)
	}

	a := app.New()
	a.SetIcon(nil) // TODO: embed icon resource

	win := fyneui.NewMainWindow(a, fyneui.Config{
		Host:  cfg.Host,
		Token: cfg.Token,
		TLS:   cfg.TLS,
	})
	win.ShowAndRun()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
