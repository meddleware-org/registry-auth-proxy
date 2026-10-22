// Package loadtest holds the load harness for the forwarding path (audit F20 remainder). It contains
// test code only, behind the "load" build tag, so it is neither built into the image nor run by
// `go test ./...`:
//
//	GOTOOLCHAIN=go1.26.10 go test -tags load -run TestLoad -v -timeout 20m ./internal/loadtest
//
// The harness builds the real binary, starts it as a separate process against a stub registry and a
// stub token service, and drives it at increasing concurrency. See load_test.go for the scenarios and
// the environment variables that shape a run.
package loadtest
