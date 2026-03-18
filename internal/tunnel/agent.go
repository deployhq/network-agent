package tunnel

import (
	"crypto/tls"
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

// RunAgent connects to the DeployHQ server and keeps reconnecting on transient
// failures.  It blocks until an unrecoverable error occurs (e.g. REJECT from
// server, or a TLS authentication error that persists after maxSSLRetries).
func RunAgent(tlsCfg *tls.Config, paths config.Paths, log *slog.Logger) error {
	serverAddr := fmt.Sprintf("%s:%s", config.ServerHost(), config.ServerPort)

	sslRetries := 0

	for {
		access, err := acl.LoadFile(paths.Access)
		if err != nil {
			return fmt.Errorf("loading access list: %w", err)
		}

		log.Info("connecting to server", "addr", serverAddr)
		sc, err := Connect(tlsCfg, serverAddr, access, log)
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
