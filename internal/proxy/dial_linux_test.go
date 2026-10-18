//go:build linux

package proxy

// The dial deadline (audit F20) needs a local address whose connect() hangs. A listening socket with a
// backlog of 0 whose accept queue is already full drops further SYNs on Linux, so a dial to it neither
// succeeds nor fails until its deadline. If the host does not behave that way the test skips; it never
// depends on a routable address or on the network.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// saturatedListener returns "127.0.0.1:port" of a listener that will not complete another connection.
func saturatedListener(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skipf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Skipf("getsockname: %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))

	// Fill the accept queue (nothing ever calls accept) until a dial no longer completes.
	for i := 0; i < 16; i++ {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			return addr
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	t.Skip("this host completes connections to a full accept queue; cannot stall a dial locally")
	return ""
}

func TestLimits_DialDeadlineEndsInBadGateway(t *testing.T) {
	buf := captureLog(t)
	addr := saturatedListener(t)

	h := newTestHandlerLimits(t, "http://"+addr, "t", limits{dialTimeout: 150 * time.Millisecond, responseHeaderTimeout: 30 * time.Second, maxInFlight: 1})
	start := time.Now()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if elapsed < 100*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("answered after %s; want about the 150 ms dial deadline (the response-header deadline is 30 s)", elapsed)
	}
	if !strings.Contains(buf.String(), `"cause":"timeout"`) || strings.Contains(buf.String(), addr) {
		t.Errorf("want the timeout class without the address in the log: %s", buf.String())
	}
	if n := len(h.inflight); n != 0 {
		t.Errorf("%d in-flight slots still held after the dial timeout", n)
	}
}
