package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testAgent returns an agent whose user-presence check is `auth`, so tests
// never trigger a real Touch ID prompt.
func testAgent(t *testing.T, ttl time.Duration, auth func(string) (bool, error)) *connAgent {
	t.Helper()
	g := newGuardedAgent(ttl)
	g.auth = auth
	return &connAgent{g: g, peer: "test"}
}

func newKey(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, sp
}

func addKey(t *testing.T, a *connAgent, priv ed25519.PrivateKey) {
	t.Helper()
	if err := a.Add(agent.AddedKey{PrivateKey: priv, Comment: "k"}); err != nil {
		t.Fatal(err)
	}
}

func counter(result bool) (func(string) (bool, error), *atomic.Int32) {
	var n atomic.Int32
	return func(string) (bool, error) { n.Add(1); return result, nil }, &n
}

func TestSignRequiresApproval(t *testing.T) {
	auth, calls := counter(true)
	a := testAgent(t, 0, auth)
	priv, pub := newKey(t)
	addKey(t, a, priv)

	for i := 0; i < 2; i++ {
		sig, err := a.Sign(pub, []byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.Verify([]byte("data"), sig); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("approve-ttl 0: want a prompt per signature (2), got %d", got)
	}
}

func TestDeclinedSignFails(t *testing.T) {
	auth, _ := counter(false)
	a := testAgent(t, 0, auth)
	priv, pub := newKey(t)
	addKey(t, a, priv)
	if _, err := a.Sign(pub, []byte("data")); err == nil {
		t.Fatal("sign succeeded after the user declined")
	}
}

func TestApprovalCachedWithinTTL(t *testing.T) {
	auth, calls := counter(true)
	a := testAgent(t, time.Minute, auth)
	priv, pub := newKey(t)
	addKey(t, a, priv)
	for i := 0; i < 3; i++ {
		if _, err := a.Sign(pub, []byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("want 1 prompt within approve-ttl, got %d", got)
	}
}

func TestUnknownKeyDoesNotPrompt(t *testing.T) {
	auth, calls := counter(true)
	a := testAgent(t, 0, auth)
	priv, _ := newKey(t)
	addKey(t, a, priv)
	_, other := newKey(t)

	if _, err := a.Sign(other, []byte("data")); err == nil {
		t.Fatal("signed with a key that isn't loaded")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("prompted %d times for a key that isn't loaded", got)
	}
}

// A pending prompt must not block `npssh lock`, and an approval that lands
// after the wipe must neither sign nor be cached.
func TestLockNotBlockedByPendingPrompt(t *testing.T) {
	prompted := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	auth := func(string) (bool, error) {
		if calls.Add(1) == 1 {
			close(prompted)
			<-release
		}
		return true, nil
	}
	a := testAgent(t, time.Minute, auth)
	priv, pub := newKey(t)
	addKey(t, a, priv)

	signErr := make(chan error, 1)
	go func() { _, err := a.Sign(pub, []byte("data")); signErr <- err }()
	<-prompted

	locked := make(chan error, 1)
	go func() { locked <- a.RemoveAll() }()
	select {
	case err := <-locked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("RemoveAll blocked while a prompt was pending")
	}

	close(release) // user approves the stale prompt
	if err := <-signErr; err == nil {
		t.Fatal("signature produced after keys were wiped")
	}

	addKey(t, a, priv) // re-adding must not inherit the stale approval
	if _, err := a.Sign(pub, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("stale approval was cached: want 2 prompts, got %d", got)
	}
}
