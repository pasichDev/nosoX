package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"unicode"
)

// rpcTokenEnv names the environment variable that carries the RPC bearer
// token. The token is never accepted on the command line, where other local
// users can read it from the process table, unit files and shell history.
const rpcTokenEnv = "NOSOX_RPC_TOKEN"

// minRPCTokenLength is the shortest accepted token, in bytes (for example 32
// hex characters from `openssl rand -hex 16`, or 43 from -base64 32).
const minRPCTokenLength = 32

// rpcTokenFromEnv returns the token from NOSOX_RPC_TOKEN, validated. An unset
// or empty variable means "no token".
func rpcTokenFromEnv(getenv func(string) string) (string, error) {
	tok := getenv(rpcTokenEnv)
	if tok == "" {
		return "", nil
	}
	if len(tok) < minRPCTokenLength {
		return "", fmt.Errorf("%s must be at least %d bytes (got %d)", rpcTokenEnv, minRPCTokenLength, len(tok))
	}
	for _, r := range tok {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return "", fmt.Errorf("%s must be printable ASCII without whitespace", rpcTokenEnv)
		}
	}
	return tok, nil
}

// validateRPCConfig rejects RPC exposure that would put the node or its token
// at risk: administration without a token off loopback, and a bearer token
// sent in clear text across a non-loopback bind.
func validateRPCConfig(addr, token string, tlsEnabled bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid RPC bind: %w", err)
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && token == "" {
		return fmt.Errorf("non-loopback RPC requires a token in %s", rpcTokenEnv)
	}
	if !loopback && !tlsEnabled {
		return errors.New("non-loopback RPC requires TLS (-rpc-tls-cert and -rpc-tls-key): the bearer token would cross the network in clear text")
	}
	return nil
}

// rpcListener binds the RPC socket before the server starts, so a taken port
// or a bad certificate stops the daemon instead of being logged while the node
// keeps running.
func rpcListener(addr, certFile, keyFile string) (net.Listener, *tls.Config, error) {
	var cfg *tls.Config
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("rpc tls: %w", err)
		}
		cfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("rpc listen %s: %w", addr, err)
	}
	return ln, cfg, nil
}

// serveRPC runs srv on ln and reports its terminal error (nil on orderly
// shutdown) on the returned channel.
func serveRPC(srv *http.Server, ln net.Listener, cfg *tls.Config) <-chan error {
	out := make(chan error, 1)
	go func() {
		var err error
		if cfg != nil {
			srv.TLSConfig = cfg
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		out <- err
	}()
	return out
}
