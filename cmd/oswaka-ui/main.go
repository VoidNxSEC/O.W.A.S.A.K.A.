//go:build !fyne

// O.W.A.S.A.K.A. Desktop UI stub.
//
// Build the full native desktop app:
//
//	nix develop   # enters shell with Go toolchain
//	go get fyne.io/fyne/v2@latest
//	go mod vendor
//	go build -tags=fyne ./cmd/oswaka-ui/
//
// The full UI requires: libGL, libX11, libXcursor, libXi (all available in the nix dev shell).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	host := flag.String("host", "localhost:8080", "OWASAKA backend host:port")
	flag.Parse()

	fmt.Fprintf(os.Stderr, `
O.W.A.S.A.K.A. Desktop UI

This binary was built WITHOUT the Fyne desktop UI (missing -tags=fyne).

To enable the full native desktop app:

  nix develop
  go get fyne.io/fyne/v2@latest
  go mod vendor
  go build -tags=fyne -o bin/oswaka-ui ./cmd/oswaka-ui/
  ./bin/oswaka-ui --host %s

The web interface is always available at http://%s
`, *host, *host)
	os.Exit(1)
}
