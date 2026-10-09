package sshdeploy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentAuth connects to the running ssh-agent and returns its keys.
//
// The agent is tried before the on-disk keys because an operator who has an
// agent running has already unlocked their key, and a passphrase-protected key
// file cannot be parsed without the passphrase anyway.
func agentAuth(socket string) ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent at %s: %w", socket, err)
	}
	// The connection is deliberately not closed: the returned signers hold it
	// open for the lifetime of the SSH client, and closing it here would make
	// every subsequent signature fail.
	ag := agent.NewClient(conn)
	signers, err := ag.Signers()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(signers) == 0 {
		conn.Close()
		return nil, errors.New("ssh-agent holds no keys")
	}
	return signers, nil
}

// CheckKeyFile verifies a private key file is usable before a deployment
// begins, so a bad path is reported immediately rather than after the operator
// has filled in a whole form.
func CheckKeyFile(path string) error {
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read the SSH private key: %w", err)
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory, not a private key", path)
	}
	// The permission check is Unix-only. Windows does not model the Unix mode
	// bits at all — Go reports 0666 for any writable file there — so applying
	// it would reject every key on the platform where the GUI client most
	// often runs. Windows access is governed by ACLs, which OpenSSH does not
	// reject either, so there is nothing to warn about.
	if runtime.GOOS != "windows" {
		// An overly permissive key file is refused by OpenSSH itself; warning
		// here saves the operator from a confusing failure during the
		// handshake.
		if st.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s is readable by other users (mode %04o); run: chmod 600 %s", path, st.Mode().Perm(), path)
		}
	}
	return nil
}
