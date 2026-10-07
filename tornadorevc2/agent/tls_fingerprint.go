package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// toUtlsCertificates converts the standard library's certificate slice
// to uTLS's type. The two structs have identical field layouts, but
// Go treats them as distinct named types. Rebuilding element-by-element
// is the only supported conversion.
func toUtlsCertificates(in []tls.Certificate) []utls.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.Certificate, len(in))
	for i, c := range in {
		out[i] = utls.Certificate{
			Certificate:                  c.Certificate,
			PrivateKey:                   c.PrivateKey,
			SupportedSignatureAlgorithms: toUtlsSigSchemes(c.SupportedSignatureAlgorithms),
			OCSPStaple:                   c.OCSPStaple,
			SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
			Leaf:                         c.Leaf,
		}
	}
	return out
}

// toUtlsSigSchemes converts a []tls.SignatureScheme to
// []utls.SignatureScheme. Both are uint16 under the hood, so each
// element converts directly.
func toUtlsSigSchemes(in []tls.SignatureScheme) []utls.SignatureScheme {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = utls.SignatureScheme(s)
	}
	return out
}

// utlsDialTLS returns a DialTLSContext implementation that produces
// a browser-shaped ClientHello when profile is not "go". When profile
// is "go" or an unknown name, the caller in main.go never installs
// this dialer, so the standard library path remains the default.
//
// Two design choices matter here:
//
//  1. ALPN is advertised as ["http/1.1"] only. Real Chrome advertises
//     ["h2", "http/1.1"], but the beacon listener speaks HTTP/1.1
//     only (Werkzeug cannot parse the HTTP/2 connection preface). If
//     we advertise h2 and the server negotiates it, net/http tries
//     to speak HTTP/2 on a connection that uTLS has already wrapped
//     as a raw stream, and the request fails. The JA3 impact of
//     advertising only http/1.1 is small — ALPN is one of the
//     smaller components of the JA3 hash.
//
//  2. The returned net.Conn is a *utls.UConn, which satisfies the
//     net.Conn interface. net/http treats it identically to a
//     *tls.Conn; the only behavioural difference is the ClientHello
//     bytes on the wire.
func utlsDialTLS(cfg *tls.Config, profile string) func(
	ctx context.Context, network, addr string,
) (net.Conn, error) {
	helloID := pickClientHelloID(profile)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Extract the SNI host. For IP-literal addresses, SNI must
		// be empty — Chrome does not send a server_name extension
		// when the connection target is an IP. Sending one anyway
		// is a fingerprintable deviation.
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		serverName := host
		if isIPLiteral(host) {
			serverName = ""
		}

		uCfg := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			RootCAs:            cfg.RootCAs,
			Certificates:       toUtlsCertificates(cfg.Certificates),
			MinVersion:         cfg.MinVersion,
			MaxVersion:         cfg.MaxVersion,
			// See the file header: http/1.1 only, to match the
			// beacon listener's capabilities.
			NextProtos: []string{"http/1.1"},
		}

		conn := utls.UClient(raw, uCfg, helloID)
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}

		// uTLS does not expose crypto/tls's VerifyConnection hook
		// across every released version, so chain verification
		// against the pinned CA runs here. Hostname verification is
		// intentionally skipped — the beacon is commonly reached by
		// IP or a redirector domain that does not match the
		// certificate CN. The chain check is what actually pins the
		// server identity.
		if cfg.RootCAs != nil {
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				conn.Close()
				return nil, fmt.Errorf(
					"utls: server presented no certificate")
			}
			opts := x509.VerifyOptions{
				Roots:         cfg.RootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
				conn.Close()
				return nil, fmt.Errorf("utls: chain verify failed: %w", err)
			}
		}
		return conn, nil
	}
}

// pickClientHelloID maps a profile name to the uTLS ClientHelloID.
// Unknown names fall back to HelloChrome_120 — Chrome is the most
// common browser on both Windows and Linux, and version 120 is
// recent enough that its JA3 hash is present in every database a
// defender would consult.
func pickClientHelloID(profile string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "firefox":
		return utls.HelloFirefox_120
	case "safari":
		return utls.HelloSafari_16_0
	case "chrome", "":
		return utls.HelloChrome_120
	default:
		return utls.HelloChrome_120
	}
}

// isIPLiteral reports whether s parses as an IPv4 or IPv6 address
// without a hostname. Used to decide whether to set SNI.
func isIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	// Handle IPv6 in brackets as produced by some URL parsers.
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return net.ParseIP(s[1:len(s)-1]) != nil
	}
	return false
}