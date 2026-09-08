// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

const sshExecDefaultPort = "22"

// sshRunCommand opens one SSH connection to t, runs cmd in a single session,
// and returns its stdout. One command per connection: every probe built on
// this reads a single fact (an OS identity file, a `uname` line) and
// disconnects — this is not a general-purpose remote-exec client, sized
// deliberately to what these probes actually need (D10: transport belongs to
// the probe).
//
// Host key verification reuses Target.TLS's existing PinSHA256/Insecure
// vocabulary (D13) rather than inventing a parallel SSH-specific config
// dialect: PinSHA256 here holds hex SHA256 of the host key's own wire
// encoding (ssh.PublicKey.Marshal()) instead of a DER certificate, but it is
// the same "pin a fingerprint, or say insecure and get warned" shape. With
// neither set, the connection is refused before a single credential is sent
// — verified live that a real OpenSSH server's auth-failure error contains
// "unable to authenticate" (golang.org/x/crypto/ssh has no typed sentinel
// for this), which is what distinguishes ErrAuth from ErrUnreachable below.
func sshRunCommand(ctx context.Context, t Target, cmd string) (stdout string, hostKeyVerified bool, err error) {
	if t.Creds.Username == "" {
		return "", false, fmt.Errorf("%w: ssh needs a username", ErrAuth)
	}

	var authMethods []ssh.AuthMethod
	switch {
	case t.Creds.PrivateKeyFile != "":
		signer, kerr := loadSSHSigner(t.Creds.PrivateKeyFile, t.Creds.Passphrase)
		if kerr != nil {
			return "", false, fmt.Errorf("%w: %w", ErrAuth, kerr)
		}
		authMethods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	case t.Creds.Password != "":
		authMethods = []ssh.AuthMethod{ssh.Password(t.Creds.Password)}
	default:
		return "", false, fmt.Errorf("%w: credential has neither private_key_file nor password", ErrAuth)
	}

	addr := defaultPort(t.Address, sshExecDefaultPort)
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = defaultTCPReadTimeout
	}

	conn, cleanup, err := dialTCP(ctx, addr, timeout)
	if err != nil {
		return "", false, err
	}
	defer cleanup()

	verified := false
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if len(t.TLS.PinSHA256) == 0 {
			if t.TLS.Insecure {
				return nil
			}
			return fmt.Errorf("host key not verified: set tls.pin_sha256 (sha256 of the host key) or tls.insecure")
		}
		sum := sha256.Sum256(key.Marshal())
		got := fmt.Sprintf("%x", sum)
		for _, want := range t.TLS.PinSHA256 {
			if strings.EqualFold(got, want) {
				verified = true
				return nil
			}
		}
		return fmt.Errorf("host key fingerprint %s matches none of the pinned tls.pin_sha256 values", got)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            t.Creds.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
	})
	if err != nil {
		return "", false, sshHandshakeErr(ctx, err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", verified, fmt.Errorf("%w: opening session: %w", ErrUnreachable, err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	if err := session.Run(cmd); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			// The session itself is fine; the remote command exited
			// nonzero. Callers decide what that means for their own
			// product (usually ErrNotSupported: wrong OS, missing file),
			// so this is returned unwrapped rather than as ErrUnreachable.
			return "", verified, fmt.Errorf("running %q: %w (stderr: %q)", cmd, err, stderrBuf.String())
		}
		return "", verified, fmt.Errorf("%w: running %q: %w (stderr: %q)", ErrUnreachable, cmd, err, stderrBuf.String())
	}

	return stdoutBuf.String(), verified, nil
}

// isSSHExitError reports whether err came from a remote command that ran and
// exited nonzero, as opposed to a connection-level failure.
func isSSHExitError(err error) bool {
	var exitErr *ssh.ExitError
	return errors.As(err, &exitErr)
}

// sshHandshakeErr classifies a failure from ssh.NewClientConn. The package
// exposes no typed sentinel for "credentials rejected" — verified live
// against a real OpenSSH server that the message it returns always contains
// this substring — so this is a deliberate, confirmed string match, not a
// guess.
func sshHandshakeErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrUnreachable, ctx.Err())
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("%w: %w", ErrAuth, err)
	}
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}

// loadSSHSigner reads a PEM private key from disk, matching how
// TLSSettings.CAFile is read as a plain filesystem path with no relative-path
// resolution magic (internal/probe/http.go).
func loadSSHSigner(path, passphrase string) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("private_key_file %s: %w", path, err)
	}
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(pem)
}
