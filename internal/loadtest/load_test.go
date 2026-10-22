//go:build load

package loadtest

// Load harness for the forwarding path (audit F20 remainder). It builds the real binary, runs it as its
// own process (so the memory and CPU read are the proxy's alone) against a stub registry and a stub token
// service in this process, and drives it with an increasing number of concurrent clients.
//
// What it measures per step: requests per second, client-side latency (p50, p99, max), the status mix
// (200 and the 503 `busy` answers of the in-flight bound), the proxy's CPU time per request (utime+stime
// from /proc) and its peak resident set (VmHWM). CPU time per request is what sizes the container limit:
// the sustainable rate at a CPU limit L is L / cpu-per-request, whatever machine measured it.
//
// Run (the proxy is pinned to the CPU named by LOAD_PROXY_CPU, the harness to the others):
//
//	taskset -c 0-2 env LOAD_PROXY_CPU=3 GOTOOLCHAIN=go1.26.10 \
//	  go test -tags load -run TestLoad -v -timeout 20m ./internal/loadtest
//
// Environment: LOAD_SECONDS (seconds per step, default 4), LOAD_BLOB_MIB (blob size, default 64),
// LOAD_PROXY_CPU (taskset CPU list for the proxy, default none), LOAD_CPU_QUOTA and LOAD_MEM_MAX (run the
// proxy in a transient systemd user scope with that CPU quota, e.g. 20%, and memory limit, e.g. 128M, which
// is how a container limit behaves; needs `systemd-run --user`), LOAD_SCENARIO (run one scenario by name).

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- stubs ------------------------------------------------------------------------------------------

type stubRegistry struct {
	srv      *httptest.Server
	latency  time.Duration
	small    []byte
	blobSize int64
	probes   atomic.Int64
	authed   atomic.Int64
}

func scopeFor(path string) string {
	if path == "/v2/_catalog" {
		return "registry:catalog:*"
	}
	name := strings.TrimPrefix(path, "/v2/")
	for _, kw := range []string{"/manifests/", "/blobs/", "/tags/", "/referrers/"} {
		if i := strings.Index(name, kw); i >= 0 {
			name = name[:i]
			break
		}
	}
	return "repository:" + name + ":pull"
}

func newStubRegistry(latency time.Duration, blobSize int64) *stubRegistry {
	s := &stubRegistry{latency: latency, small: []byte(strings.Repeat("x", 1024)), blobSize: blobSize}
	zeros := make([]byte, 64<<10)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			s.probes.Add(1)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="http://stub/token",service="registry",scope="%s"`, scopeFor(r.URL.Path)))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.authed.Add(1)
		if s.latency > 0 {
			time.Sleep(s.latency)
		}
		if strings.Contains(r.URL.Path, "/blobs/") {
			w.Header().Set("Content-Length", strconv.FormatInt(s.blobSize, 10))
			w.Header().Set("Content-Type", "application/octet-stream")
			for left := s.blobSize; left > 0; {
				n := int64(len(zeros))
				if left < n {
					n = left
				}
				if _, err := w.Write(zeros[:n]); err != nil {
					return
				}
				left -= n
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(s.small)))
		_, _ = w.Write(s.small)
	}))
	return s
}

type stubTokenService struct {
	srv     *httptest.Server
	latency time.Duration
	calls   atomic.Int64
}

func newStubTokenService(latency time.Duration) *stubTokenService {
	s := &stubTokenService{latency: latency}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s.latency > 0 {
			time.Sleep(s.latency)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"t","expires_in":300,"issued_at":%q}`, time.Now().UTC().Format(time.RFC3339))
	}))
	return s
}

// ---- the proxy process -----------------------------------------------------------------------------

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func buildProxy(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "auth-proxy-load-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "auth-proxy")
		cmd := exec.Command("go", "build", "-trimpath", "-o", binPath, "../../cmd/server")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

type proxyProc struct {
	cmd  *exec.Cmd
	addr string
}

func startProxy(t *testing.T, upstream, tokenEndpoint string) *proxyProc {
	t.Helper()
	bin := buildProxy(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("load-test-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Optional wrappers, outermost first: a transient systemd scope with the container's CPU quota and
	// memory limit (LOAD_CPU_QUOTA, LOAD_MEM_MAX), then CPU pinning (LOAD_PROXY_CPU). Both exec the next
	// program, so the process measured through /proc is the proxy itself.
	argv := []string{bin}
	if cpu := os.Getenv("LOAD_PROXY_CPU"); cpu != "" {
		argv = append([]string{"taskset", "-c", cpu}, argv...)
	}
	if q := os.Getenv("LOAD_CPU_QUOTA"); q != "" {
		scope := []string{"systemd-run", "--user", "--scope", "-q", "-p", "CPUQuota=" + q}
		if m := os.Getenv("LOAD_MEM_MAX"); m != "" {
			scope = append(scope, "-p", "MemoryMax="+m)
		}
		argv = append(scope, argv...)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{
		"PORT=" + strconv.Itoa(port),
		"UPSTREAM_URL=" + upstream,
		"TOKEN_ENDPOINT=" + tokenEndpoint + "/token",
		"CLIENT_SECRET_FILE=" + secret,
		"LOG_LEVEL=info", // as deployed
	}
	for _, k := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} { // for systemd-run
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proxyProc{cmd: cmd, addr: "127.0.0.1:" + strconv.Itoa(port)}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + p.addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return p
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("proxy did not become healthy")
	return nil
}

// cpuSeconds is the proxy's user+system CPU time.
func (p *proxyProc) cpuSeconds(t *testing.T) float64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:]) // fields after "(comm) "
	ut, _ := strconv.ParseFloat(f[11], 64)               // utime is field 14 overall, index 11 here
	st, _ := strconv.ParseFloat(f[12], 64)
	return (ut + st) / 100 // USER_HZ
}

// status reads a kB field (VmRSS, VmHWM) of /proc/<pid>/status in MiB.
func (p *proxyProc) status(t *testing.T, key string) float64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line)
			kb, _ := strconv.ParseFloat(f[1], 64)
			return kb / 1024
		}
	}
	return 0
}

// ---- the load generator ----------------------------------------------------------------------------

type step struct {
	conc                int
	dur                 time.Duration
	ok, busy, other, ne int64
	bytes               int64
	lat                 []time.Duration
	cpuSec              float64
}

func (s *step) rps() float64 { return float64(s.ok+s.busy+s.other) / s.dur.Seconds() }

func (s *step) pct(q float64) time.Duration {
	if len(s.lat) == 0 {
		return 0
	}
	return s.lat[int(float64(len(s.lat)-1)*q)]
}

// drive runs conc clients for dur against the proxy. pathFn maps the request counter to a path.
func drive(t *testing.T, p *proxyProc, conc int, dur time.Duration, keepalive bool, pathFn func(n int64) string) *step {
	t.Helper()
	tr := &http.Transport{MaxIdleConnsPerHost: conc, DisableKeepAlives: !keepalive, Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	var counter atomic.Int64
	res := &step{conc: conc}
	var mu sync.Mutex
	var wg sync.WaitGroup
	cpu0 := p.cpuSeconds(t)
	start := time.Now()
	stop := start.Add(dur)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lat []time.Duration
			var ok, busy, other, ne, bytes int64
			for time.Now().Before(stop) {
				t0 := time.Now()
				resp, err := client.Get("http://" + p.addr + pathFn(counter.Add(1)))
				if err != nil {
					ne++
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				lat = append(lat, time.Since(t0))
				switch resp.StatusCode {
				case http.StatusOK:
					ok++
					bytes += n
				case http.StatusServiceUnavailable:
					busy++
				default:
					other++
				}
			}
			mu.Lock()
			res.ok, res.busy, res.other, res.ne, res.bytes = res.ok+ok, res.busy+busy, res.other+other, res.ne+ne, res.bytes+bytes
			res.lat = append(res.lat, lat...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	res.dur = time.Since(start)
	res.cpuSec = p.cpuSeconds(t) - cpu0
	sort.Slice(res.lat, func(i, j int) bool { return res.lat[i] < res.lat[j] })
	return res
}

func report(t *testing.T, p *proxyProc, s *step, extra string) {
	t.Helper()
	served := s.ok + s.busy + s.other
	cpuPerReq := 0.0
	if served > 0 {
		cpuPerReq = s.cpuSec / float64(served) * 1e6 // microseconds
	}
	t.Logf("conc=%-4d req/s=%-9.0f 200=%-7d 503=%-7d other=%-3d err=%-3d p50=%-9s p99=%-9s max=%-9s cpu/req=%-7.0fus proxyCPU=%4.0f%% rssPeak=%.1fMiB rssNow=%.1fMiB MiB/s=%.0f %s",
		s.conc, s.rps(), s.ok, s.busy, s.other, s.ne,
		s.pct(0.50).Round(10*time.Microsecond), s.pct(0.99).Round(10*time.Microsecond), s.pct(1).Round(10*time.Microsecond),
		cpuPerReq, 100*s.cpuSec/s.dur.Seconds(), p.status(t, "VmHWM"), p.status(t, "VmRSS"),
		float64(s.bytes)/(1<<20)/s.dur.Seconds(), extra)
}

func seconds() time.Duration {
	n, _ := strconv.Atoi(os.Getenv("LOAD_SECONDS"))
	if n <= 0 {
		n = 4
	}
	return time.Duration(n) * time.Second
}

func want(name string) bool {
	s := os.Getenv("LOAD_SCENARIO")
	return s == "" || s == name
}

// ---- scenarios -------------------------------------------------------------------------------------

// hit: a steady-state read, token cached, 1 KiB response. The UI's normal traffic.
func runHit(t *testing.T, name string, upstreamLatency time.Duration, keepalive bool, ladder []int) {
	if !want(name) {
		return
	}
	t.Run(name, func(t *testing.T) {
		for _, conc := range ladder {
			reg := newStubRegistry(upstreamLatency, 0)
			tok := newStubTokenService(0)
			p := startProxy(t, reg.srv.URL, tok.srv.URL)
			path := func(int64) string { return "/v2/app/manifests/latest" }
			if resp, err := http.Get("http://" + p.addr + path(0)); err == nil { // warm: one token
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			s := drive(t, p, conc, seconds(), keepalive, path)
			report(t, p, s, fmt.Sprintf("tokenCalls=%d", tok.calls.Load()))
			if s.other != 0 || s.ne != 0 {
				t.Errorf("conc %d: %d non-200/503 answers and %d client errors", conc, s.other, s.ne)
			}
			reg.srv.Close()
			tok.srv.Close()
		}
	})
}

// blob: large streamed downloads; the point is resident memory with many streams open.
func runBlob(t *testing.T) {
	const name = "blob-stream"
	if !want(name) {
		return
	}
	t.Run(name, func(t *testing.T) {
		mib, _ := strconv.Atoi(os.Getenv("LOAD_BLOB_MIB"))
		if mib <= 0 {
			mib = 64
		}
		digest := "sha256:" + strings.Repeat("a", 64)
		for _, conc := range []int{1, 8, 32, 64, 96} {
			reg := newStubRegistry(0, int64(mib)<<20)
			tok := newStubTokenService(0)
			p := startProxy(t, reg.srv.URL, tok.srv.URL)
			path := func(int64) string { return "/v2/app/blobs/" + digest }
			s := drive(t, p, conc, seconds(), true, path)
			report(t, p, s, fmt.Sprintf("blob=%dMiB", mib))
			if s.other != 0 {
				t.Errorf("conc %d: %d unexpected statuses", conc, s.other)
			}
			reg.srv.Close()
			tok.srv.Close()
		}
	})
}

// storm: every request names a repository never seen before, so each costs a probe, a token request and a
// retry (audit F3 residual). The token service answers in 5 ms and the registry in 2 ms.
func runStorm(t *testing.T) {
	const name = "cold-miss-storm"
	if !want(name) {
		return
	}
	t.Run(name, func(t *testing.T) {
		for _, conc := range []int{16, 64, 256} {
			reg := newStubRegistry(2*time.Millisecond, 0)
			tok := newStubTokenService(5 * time.Millisecond)
			p := startProxy(t, reg.srv.URL, tok.srv.URL)
			path := func(n int64) string { return fmt.Sprintf("/v2/r%d/tags/list", n) }
			s := drive(t, p, conc, seconds(), true, path)
			report(t, p, s, fmt.Sprintf("tokenCalls/s=%.0f probes/s=%.0f", float64(tok.calls.Load())/s.dur.Seconds(), float64(reg.probes.Load())/s.dur.Seconds()))
			if s.other != 0 || s.ne != 0 {
				t.Errorf("conc %d: %d non-200/503 answers and %d client errors", conc, s.other, s.ne)
			}
			reg.srv.Close()
			tok.srv.Close()
		}
	})
}

func TestLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("load harness")
	}
	runHit(t, "hit-keepalive", 0, true, []int{1, 4, 16, 32, 48, 64, 128, 256})
	runHit(t, "hit-new-connection", 0, false, []int{1, 16, 64, 128, 256})
	runHit(t, "hit-upstream-20ms", 20*time.Millisecond, true, []int{16, 64, 128, 256})
	runBlob(t)
	runStorm(t)
}
