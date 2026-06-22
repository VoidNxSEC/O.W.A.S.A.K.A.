// Package ebpf watches outbound TCP connect() attempts on the host
// OWASAKA itself runs on (not remote hosts) using github.com/cilium/ebpf
// — a pure-Go eBPF loader, no Rust/Aya toolchain. See probe.c for the
// kernel-side tap; all Tor-port/Tor-IP filtering happens in Go (service.go).
package ebpf

// The C source and its vmlinux.h CO-RE header live in bpf/ rather than
// this package directory — Go's build refuses any .c file sitting in a
// non-cgo package directory, so bpf2go's source/output are split.
//
// arm64 needs its own vmlinux.h (BTF dumped from an arm64 kernel) —
// bpf/vmlinux.h was dumped from the x86_64 dev/CI host, so only amd64
// is generated here. Re-run on an arm64 host with its own vmlinux.h to
// add arm64 support.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang probe bpf/probe.c -- -I bpf
