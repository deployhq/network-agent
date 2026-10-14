package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"time"

	"github.com/deployhq/network-agent/internal/acl"
	"github.com/deployhq/network-agent/internal/config"
)

const (
	maxSSLRetries    = 4
	reconnectMinSecs = 10
	reconnectMaxSecs = 20
)

// Options carries what the tunnel needs beyond the TLS connection itself.
//
// The zero value is valid and disables in-band certificate renewal, which is
// what tests that only exercise the proxy protocol want.
type Options struct {
	// Version is this build's version, reported to the server as
	// "go/<Version>" when asking whether the client certificate needs
	// re-issuing. The server has no other way to tell a Go agent from a Ruby
	// one, or to know which release it is talking to.
	Version string

	// Paths locates agent.crt and agent.key. Renewal replaces the certificate
	// in place; the key is never touched.
	Paths config.Paths

	// CARoots are the trust anchors a renewed certificate must chain to.
	// Leaving it nil disables certificate renewal entirely.
	CARoots *x509.CertPool
}

// RunAgent connects to the DeployHQ server and keeps reconnecting on transient
// failures.  It blocks until an unrecoverable error occurs (e.g. REJECT from
// server, or a TLS authentication error that persists after maxSSLRetries).
func RunAgent(tlsCfg *tls.Config, opts Options, log *slog.Logger) error {
	serverAddr := fmt.Sprintf("%s:%s", config.ServerHost(), config.ServerPort)

	sslRetries := 0

	for {
		access, err := acl.LoadFile(opts.Paths.Access)
		if err != nil {
			return fmt.Errorf("loading access list: %w", err)
		}

		log.Info("connecting to server", "addr", serverAddr)
		sc, err := Connect(tlsCfg, serverAddr, access, opts, log)
		if err != nil {
			// TLS-level failure: apply retry counter (matches Ruby's 4-retry limit)
			sslRetries++
			if sslRetries >= maxSSLRetries {
				return fmt.Errorf("too many connection failures: %w", err)
			}
			log.Info("connection error, retrying", "err", err, "attempt", sslRetries)
			sleepRandom()
			continue
		}

		// Reset SSL retry counter on successful connect
		sslRetries = 0

		runErr := sc.Run()

		var rejected ErrRejected
		if errors.As(runErr, &rejected) {
			// REJECT means do not reconnect
			return runErr
		}

		if errors.Is(runErr, ErrCertificateRenewed) {
			// Not a failure: the certificate on disk has been replaced and a
			// fresh handshake is what makes the agent present it. Reconnect
			// immediately, and deliberately without touching sslRetries — this
			// connection succeeded.
			log.Info("reconnecting to present the renewed certificate")
			continue
		}

		if runErr == nil || errors.Is(runErr, io.EOF) {
			// Clean disconnect (RECONNECT or EOF): reconnect immediately
			log.Info("server disconnected, reconnecting")
			continue
		}

		// Any other error: reconnect with backoff
		log.Info("server connection lost, reconnecting", "err", runErr)
		sleepRandom()
	}
}

func sleepRandom() {
	secs := reconnectMinSecs + rand.Intn(reconnectMaxSecs-reconnectMinSecs+1)
	time.Sleep(time.Duration(secs) * time.Second)
}
