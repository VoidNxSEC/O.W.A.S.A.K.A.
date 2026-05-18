# Sprint demos

End-to-end demonstrations recorded as build-tagged Go tests so they
are reproducible, asserted, and easy to embed in sprint reviews. Each
demo prints a structured transcript that doubles as the acceptance
record for its sprint.

## Running

```bash
make demo-sprint1        # Sprint 1: identity & authentication
# more demos land per sprint
```

The build tag (`-tags=demo`) keeps these out of the regular `go test`
runs so CI stays fast.

## Recording an asciinema cast

For visual sprint reviews:

```bash
asciinema rec docs/demos/sprint-01.cast -- bash -lc "nix develop --command make demo-sprint1"
asciinema upload docs/demos/sprint-01.cast    # optional, when sharing externally
```

The `.cast` files are JSON and play back deterministically; commit
them next to the transcript so reviewers can pick either format.

## Transcripts

| File                              | Sprint | Scope                                                                  |
|-----------------------------------|--------|------------------------------------------------------------------------|
| `sprint-01-transcript.txt`        | 1      | Register → login (pwd+TOTP) → JWT → API call → JWKS verify → revoke    |
| `sprint-02-transcript.txt`        | 2      | 4 baseline roles matrix → in-process mTLS-cn → hot-reload → analyst recipe → malformed-keeps-prior |

## Anatomy of a demo test

Each `internal/identity/demo/*_test.go` (or future
`internal/*/demo/*_test.go`) follows the same shape:

- `//go:build demo` so it stays out of CI.
- Banner header (`╔══...╗`) and per-step banners (`STEP N — …`) so the
  transcript reads top-to-bottom like a narrative.
- `must(t, err, "…")` to fail loudly if any step regresses.
- A final `Acceptance` checklist mirroring the ADR's acceptance
  criteria so reviewers can tick boxes mechanically.

When sprint demos regress, the test fails and CI (eventually) refuses
the regression. Until CI runs them, run them locally as part of
sprint close.
