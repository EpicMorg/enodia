// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshTestServer is a throwaway in-process SSH server standing in for a real
// sshd the same way mongoServer's raw TCP listener stands in for a real
// mongod: it speaks the real golang.org/x/crypto/ssh server protocol (real
// handshake, real auth, real exec channel), not a hand-rolled stub of it, so
// what's under test is the client-side code in sshexec.go against the same
// library's own server implementation.
//
// outputs maps an exact command string to the stdout it should answer with,
// exiting 0; a command not in the map exits 1 with empty output, standing in
// for "cat: No such file or directory" on a host that isn't this product.
func sshTestServer(t *testing.T, username, password string, authorizedKey ssh.PublicKey, outputs map[string]string) (addr string, hostKeyFingerprint string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	fingerprint := fmt.Sprintf("%x", sum)

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if password != "" && conn.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong credentials")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKey != nil && conn.User() == username && bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		nConn, err := ln.Accept()
		if err != nil {
			return
		}
		serverConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
		if err != nil {
			return
		}
		defer serverConn.Close()
		go ssh.DiscardRequests(reqs)

		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(ssh.UnknownChannelType, "only session supported")
				continue
			}
			channel, requests, err := newChan.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for req := range requests {
					if req.Type != "exec" {
						if req.WantReply {
							_ = req.Reply(false, nil)
						}
						continue
					}
					// exec payload: uint32 length-prefixed command string.
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					out, ok := outputs[string(req.Payload[4:])]
					exitCode := uint32(0)
					if !ok {
						exitCode = 1
					}
					_, _ = channel.Write([]byte(out))
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{exitCode}))
					return
				}
			}()
		}
	}()

	return ln.Addr().String(), fingerprint
}

func TestSSHRunCommandPasswordAuthAndPin(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{
		"echo hi": "hi\n",
	})

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	out, verified, err := sshRunCommand(context.Background(), target, "echo hi")
	if err != nil {
		t.Fatalf("sshRunCommand: %v", err)
	}
	if out != "hi\n" {
		t.Fatalf("got output %q", out)
	}
	if !verified {
		t.Fatal("expected host key to verify against the pinned fingerprint")
	}
}

func TestSSHRunCommandWrongPasswordIsAuthError(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil)

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "wrong"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, _, err := sshRunCommand(context.Background(), target, "echo hi")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSSHRunCommandNoHostKeyPinIsRefused(t *testing.T) {
	addr, _ := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{"echo hi": "hi\n"})

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		Timeout: 2 * time.Second,
	}

	_, _, err := sshRunCommand(context.Background(), target, "echo hi")
	if err == nil {
		t.Fatal("expected an error with no pin_sha256 and no insecure flag")
	}
}

func TestSSHRunCommandInsecureSkipsHostKeyCheck(t *testing.T) {
	addr, _ := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{"echo hi": "hi\n"})

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{Insecure: true},
		Timeout: 2 * time.Second,
	}

	out, verified, err := sshRunCommand(context.Background(), target, "echo hi")
	if err != nil {
		t.Fatalf("sshRunCommand: %v", err)
	}
	if out != "hi\n" {
		t.Fatalf("got output %q", out)
	}
	if verified {
		t.Fatal("insecure mode never sets verified=true, even on a successful connection")
	}
}

func TestSSHRunCommandNonzeroExitIsExitError(t *testing.T) {
	addr, fp := sshTestServer(t, "probeuser", "probepass", nil, nil) // no commands configured -> exit 1

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	_, _, err := sshRunCommand(context.Background(), target, "cat /etc/os-release")
	if !isSSHExitError(err) {
		t.Fatalf("got %v, want an *ssh.ExitError", err)
	}
}

func TestSSHRunCommandPrivateKeyAuth(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	addr, fp := sshTestServer(t, "probeuser", "", signer.PublicKey(), map[string]string{
		"echo hi": "hi\n",
	})

	target := Target{
		Address: addr,
		Creds:   Credentials{Username: "probeuser", PrivateKeyFile: keyPath},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
	}

	out, _, err := sshRunCommand(context.Background(), target, "echo hi")
	if err != nil {
		t.Fatalf("sshRunCommand: %v", err)
	}
	if out != "hi\n" {
		t.Fatalf("got output %q", out)
	}
}
