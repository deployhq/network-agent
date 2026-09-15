package tunnel

import (
	"errors"

	"github.com/deployhq/network-agent/internal/certrenew"
	"github.com/deployhq/network-agent/internal/protocol"
)

// implementationPrefix identifies this agent to the server. The Ruby gem sends
// "ruby/<version>" over the same command, which is the only way the backend can
// tell the two implementations apart — nothing else on the wire carries it.
const implementationPrefix = "go/"

// devVersion is what an unreleased build reports, matching main.Version's
// default so a locally built agent is never mistaken for a release.
const devVersion = "dev"

// ErrCertificateRenewed asks RunAgent for a fresh connection so the newly
// installed certificate is actually presented. It is a signal, not a failure,
// and must never count towards the TLS retry budget.
var ErrCertificateRenewed = errors.New("certificate renewed")

// renewalEnabled reports whether this connection may install a new certificate.
// Renewal needs somewhere to write and something to verify against; without
// both, a RENEW_RESPONSE is ignored rather than acted on blindly.
func (sc *ServerConn) renewalEnabled() bool {
	return sc.opts.CARoots != nil &&
		sc.opts.Paths.Certificate != "" &&
		sc.opts.Paths.Key != ""
}

// sendRenewRequest asks the server, once per connection, whether this agent's
// client certificate needs re-issuing under a newer CA. The server decides;
// the agent only reports who it is.
func (sc *ServerConn) sendRenewRequest() {
	if !sc.renewalEnabled() {
		return
	}
	version := sc.opts.Version
	if version == "" {
		version = devVersion
	}
	identifier := implementationPrefix + version

	select {
	case sc.serverSend <- protocol.EncodeRenewRequest(identifier):
		sc.log.Debug("sent certificate renewal request", "agent", identifier)
	default:
		// Unreachable in practice — the queue is empty at this point — but a
		// blocked send here would stall the whole connection, and renewal is
		// never worth that.
		sc.log.Warn("could not queue certificate renewal request")
	}
}

// handleRenewResponse acts on the server's answer to sendRenewRequest.
//
// It returns ErrCertificateRenewed when a new certificate has been installed,
// which tears this connection down so the next one presents it. Every other
// outcome — including every kind of failure — returns nil and leaves the
// connection running: a renewal that cannot happen is never a reason to take a
// working tunnel, or the process, down.
func (sc *ServerConn) handleRenewResponse(payload []byte) error {
	status, body, ok := protocol.ParseRenewResponse(payload)
	if !ok {
		sc.log.Warn("malformed RENEW_RESPONSE")
		return nil
	}

	if !sc.renewalEnabled() {
		sc.log.Warn("ignoring RENEW_RESPONSE: certificate renewal is not configured")
		return nil
	}

	switch status {
	case protocol.RenewStatusCurrent:
		sc.log.Debug("certificate is current, no renewal needed")
		return nil

	case protocol.RenewStatusError:
		sc.log.Warn("server could not renew certificate", "reason", string(body))
		return nil

	case protocol.RenewStatusRenewed:
		return sc.installRenewedCertificate(body)

	default:
		sc.log.Warn("unknown RENEW_RESPONSE status", "status", status)
		return nil
	}
}

func (sc *ServerConn) installRenewedCertificate(certPEM []byte) error {
	current, err := certrenew.LoadCurrent(sc.opts.Paths.Certificate)
	if err != nil {
		sc.log.Warn("certificate renewal skipped", "err", err)
		return nil
	}

	installed, err := certrenew.Apply(certrenew.Request{
		CertPath:     sc.opts.Paths.Certificate,
		KeyPath:      sc.opts.Paths.Key,
		Roots:        sc.opts.CARoots,
		Current:      current,
		CandidatePEM: certPEM,
	})
	switch {
	case errors.Is(err, certrenew.ErrUnchanged):
		// The server offered the certificate the agent already presents.
		// Reconnecting would change nothing, and a server that keeps answering
		// this way would spin the agent through connect-renew-reconnect
		// forever. Stay on this connection.
		sc.log.Debug("server offered the certificate already installed, nothing to do")
		return nil

	case err != nil:
		// Nothing was written; the agent carries on with the certificate it
		// has and will ask again on the next connection.
		sc.log.Warn("certificate renewal rejected", "err", err)
		return nil
	}

	sc.log.Info("certificate renewed",
		"issuer", installed.Issuer.CommonName,
		"serial", installed.SerialNumber.String(),
		"expires", installed.NotAfter.UTC().Format("2006-01-02"))

	return ErrCertificateRenewed
}
