package monitor

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestCheckSSLEndpointLocalTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := checkSSLEndpoint(ctx, host, port, "", false, true, 5*time.Second)
	if err != nil {
		t.Fatalf("check endpoint: %v", err)
	}
	if res.HTTPSStatus != "ok" {
		t.Fatalf("https status = %q", res.HTTPSStatus)
	}
	if res.NotAfter == nil || !res.NotAfter.After(time.Now()) {
		t.Fatalf("unexpected certificate expiry: %v", res.NotAfter)
	}
	if res.ChainValid {
		t.Fatal("self-signed test certificate should not have a publicly valid chain")
	}
	if !res.HostnameValid {
		t.Fatal("httptest certificate should match its local IP")
	}
	if len(res.SAN) == 0 {
		t.Fatal("expected SAN entries")
	}
}

func TestCheckSSLEndpointRejectsPrivateTarget(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := checkSSLEndpoint(ctx, host, port, "", false, false, 3*time.Second)
	if err == nil {
		t.Fatal("expected private target to be rejected")
	}
}
