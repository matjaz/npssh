package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// guardedAgent wraps an in-memory keyring and requires user presence
// (Touch ID / login password on macOS) before every signature.
type guardedAgent struct {
	base       agent.ExtendedAgent
	approveTTL time.Duration
	auth       func(reason string) (bool, error)

	// promptMu serialises user-presence prompts so they never stack. It is
	// held for as long as a prompt is on screen, so nothing else may wait on it.
	promptMu sync.Mutex

	mu        sync.Mutex // guards approvals and gen; never held across a prompt
	approvals map[string]time.Time
	gen       uint64 // bumped on every key removal; invalidates in-flight approvals
}

func newGuardedAgent(approveTTL time.Duration) *guardedAgent {
	return &guardedAgent{
		base:       agent.NewKeyring().(agent.ExtendedAgent),
		approveTTL: approveTTL,
		auth:       authenticate,
		approvals:  map[string]time.Time{},
	}
}

// connAgent is the per-connection view; it knows which process is talking.
type connAgent struct {
	g    *guardedAgent
	peer string
}

func (c *connAgent) List() ([]*agent.Key, error) { return c.g.base.List() }

func (c *connAgent) Add(k agent.AddedKey) error {
	// We confirm every use ourselves, so accept (and ignore) ssh-add -c.
	k.ConfirmBeforeUse = false
	log.Printf("key added: %q (lifetime %ds) by %s", k.Comment, k.LifetimeSecs, c.peer)
	return c.g.base.Add(k)
}

func (c *connAgent) Remove(k ssh.PublicKey) error {
	c.g.forget(k)
	return c.g.base.Remove(k)
}

func (c *connAgent) RemoveAll() error {
	c.g.mu.Lock()
	c.g.approvals = map[string]time.Time{}
	c.g.gen++
	c.g.mu.Unlock()
	log.Printf("all keys removed by %s", c.peer)
	return c.g.base.RemoveAll()
}

func (c *connAgent) Lock(p []byte) error   { return c.g.base.Lock(p) }
func (c *connAgent) Unlock(p []byte) error { return c.g.base.Unlock(p) }

func (c *connAgent) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("signers not exposed")
}

func (c *connAgent) Sign(k ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(k, data, 0)
}

func (c *connAgent) SignWithFlags(k ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if err := c.g.approve(k, c.peer); err != nil {
		log.Printf("DENIED sign with %s for %s: %v", ssh.FingerprintSHA256(k), c.peer, err)
		return nil, err
	}
	return c.g.base.SignWithFlags(k, data, flags)
}

func (c *connAgent) Extension(t string, contents []byte) ([]byte, error) {
	return c.g.base.Extension(t, contents)
}

func (g *guardedAgent) forget(k ssh.PublicKey) {
	g.mu.Lock()
	delete(g.approvals, ssh.FingerprintSHA256(k))
	g.gen++
	g.mu.Unlock()
}

// lookup returns the comment of a loaded key, and whether it is loaded at all.
func (g *guardedAgent) lookup(k ssh.PublicKey) (string, bool) {
	keys, err := g.base.List()
	if err != nil {
		return "", false
	}
	blob := k.Marshal()
	for _, kk := range keys {
		if bytes.Equal(kk.Blob, blob) {
			return kk.Comment, true
		}
	}
	return "", false
}

func (g *guardedAgent) cachedApproval(fp string) (ok bool, gen uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, found := g.approvals[fp]
	return g.approveTTL > 0 && found && time.Since(t) < g.approveTTL, g.gen
}

func (g *guardedAgent) approve(k ssh.PublicKey, peer string) error {
	fp := ssh.FingerprintSHA256(k)
	// Don't put up a prompt for a key we couldn't sign with anyway.
	name, loaded := g.lookup(k)
	if !loaded {
		return errors.New("key not loaded")
	}

	g.promptMu.Lock()
	defer g.promptMu.Unlock()

	ok, gen := g.cachedApproval(fp) // re-checked after waiting: a queued request may now be covered
	if ok {
		log.Printf("sign with %s for %s (cached approval)", fp, peer)
		return nil
	}

	if name == "" {
		name = fp
	}
	reason := fmt.Sprintf("use SSH key \"%s\" for %s", name, peer)
	approved, err := g.auth(reason)
	if err != nil {
		return err
	}
	if !approved {
		return errors.New("user declined")
	}
	log.Printf("APPROVED sign with %s (%s) for %s", fp, name, peer)
	if g.approveTTL > 0 {
		g.mu.Lock()
		if g.gen == gen { // keys were wiped while the prompt was up: don't cache
			g.approvals[fp] = time.Now()
		}
		g.mu.Unlock()
	}
	return nil
}
