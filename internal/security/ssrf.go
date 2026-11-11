package security

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// SafeDialer rejects connections to private, loopback and link-local addresses
// after DNS resolution. The Control callback sees the concrete IP, so DNS
// rebinding cannot bypass the check.
func SafeControl(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	if allowPrivate {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("目标地址无效: %w", err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return errors.New("目标地址未解析为 IP，已拒绝")
		}
		if !IsPublicIP(ip) {
			return errors.New("目标地址指向内网或保留地址，已拒绝连接")
		}
		return nil
	}
}

func SafeDialContext(allowPrivate bool, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	d.Control = SafeControl(allowPrivate)
	return d.DialContext
}

func NewSafeTransport(allowPrivate bool, timeout time.Duration, insecure bool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           SafeDialContext(allowPrivate, timeout),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure, // only used by explicit diagnostic paths
		},
	}
}

func NewSafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewSafeTransport(allowPrivate, timeout, false),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("重定向次数过多")
			}
			if req.URL.Scheme != "https" {
				return errors.New("重定向目标必须使用 HTTPS")
			}
			if req.URL.User != nil {
				return errors.New("重定向目标不允许包含凭据")
			}
			return nil
		},
	}
}

func ValidatePublicHostname(host string) error {
	if _, err := url.Parse("https://" + host); err != nil {
		return err
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return errors.New("主机名无法解析")
	}
	for _, ip := range ips {
		if !IsPublicIP(ip) {
			return errors.New("目标解析到内网或保留地址")
		}
	}
	return nil
}
