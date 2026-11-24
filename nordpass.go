package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Keys live in NordPass as Secure Notes with a hidden custom field
// "private_key" holding the base64-encoded OpenSSH private key (base64 so the
// multi-line PEM survives a single-line field). They are read with the
// documented `np inject` reference form  {{<Title>/custom:private_key}}.
const fieldPriv = "private_key"

func npBin() string {
	if p := os.Getenv("NPSSH_NP"); p != "" {
		return p
	}
	return "np"
}

func validTitle(t string) error {
	if t == "" || strings.ContainsAny(t, "/:{}\n") {
		return fmt.Errorf("item title %q must not be empty or contain / : { }", t)
	}
	return nil
}

// npOutput runs np non-interactively and returns stdout, folding stderr into
// the error so failures are readable.
func npOutput(args ...string) ([]byte, error) {
	var out, stderr bytes.Buffer
	cmd := exec.Command(npBin(), args...)
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("np %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

// npFetchPrivate returns the raw (PEM) private key stored in item `title`.
// The vault must already be unlocked (npEnsureUnlocked).
func npFetchPrivate(title string) ([]byte, error) {
	tmpl, err := os.CreateTemp("", "npssh-*.tmpl")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpl.Name())
	// The template contains only the reference, never the secret.
	fmt.Fprintf(tmpl, "{{%s/custom:%s}}", title, fieldPriv)
	tmpl.Close()

	out, err := npOutput("inject", "--in", tmpl.Name())
	if err != nil {
		return nil, fmt.Errorf("%q: %v", title, err)
	}
	val := strings.TrimSpace(string(out))
	if val == "" || strings.Contains(val, "{{") {
		return nil, fmt.Errorf("item %q has no %q field", title, fieldPriv)
	}
	return decodeStored(val), nil
}

func decodeStored(val string) []byte {
	if strings.Contains(val, "PRIVATE KEY") { // stored as raw PEM
		return []byte(val + "\n")
	}
	if b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(val), "")); err == nil {
		return b
	}
	return []byte(val)
}

// npTitleCount returns how many active vault items are titled exactly
// `title` — the same match `np inject` uses to resolve a title reference.
func npTitleCount(title string) (int, error) {
	out, err := npOutput("item", "list", "--search", title, "--format", "json")
	if err != nil {
		return 0, err
	}
	var items []struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(out, &items); err != nil {
		return 0, fmt.Errorf("np item list: unexpected output: %v", err)
	}
	n := 0
	for _, it := range items {
		if it.Title == title {
			n++
		}
	}
	return n, nil
}

// npCreate stores a key as a new Secure Note. The secret goes via stdin
// ("-"), so it never appears in argv / `ps`.
func npCreate(title, pub string, pemKey []byte, folder string) error {
	args := []string{"item", "create", "--type", "note", "--name", title,
		"--note", "SSH key managed by npssh\n" + pub,
		"--text-field", "public_key=" + pub,
		"--hidden-field", fieldPriv + "=-"}
	if folder != "" {
		args = append(args, "--folder", folder)
	}
	cmd := exec.Command(npBin(), args...)
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(pemKey))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func npInteractive(args ...string) error {
	cmd := exec.Command(npBin(), args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

type npStatus struct {
	Authenticated bool  `json:"authenticated"`
	SessionValid  *bool `json:"sessionValid"` // null when the server couldn't be reached
	VaultUnlocked bool  `json:"vaultUnlocked"`
}

func npWhoami() (npStatus, error) {
	var st npStatus
	out, err := npOutput("whoami", "--format", "json")
	if jerr := json.Unmarshal(out, &st); jerr != nil {
		if err == nil {
			err = fmt.Errorf("np whoami: unexpected output: %v", jerr)
		}
		return st, err
	}
	return st, nil // np may exit non-zero when signed out but still report status
}

// npEnsureUnlocked makes sure the np vault is readable, running `np signin`
// and/or `np unlock` interactively only when needed. Checking first (rather
// than retrying after a failed read) keeps "vault locked" from being mistaken
// for "item missing".
func npEnsureUnlocked() error {
	if _, err := exec.LookPath(npBin()); err != nil {
		return errors.New("NordPass CLI `np` not found — brew install nordpass/tap/np")
	}
	st, err := npWhoami()
	if err != nil {
		return err
	}
	if !st.Authenticated || (st.SessionValid != nil && !*st.SessionValid) {
		fmt.Fprintln(os.Stderr, "→ signing in to the NordPass CLI")
		args := []string{"signin"}
		if st.Authenticated { // session expired: plain signin would say "already signed in"
			args = append(args, "--force")
		}
		if err := npInteractive(args...); err != nil {
			return fmt.Errorf("np signin: %v", err)
		}
		if st, err = npWhoami(); err != nil {
			return err
		}
	}
	if !st.VaultUnlocked {
		fmt.Fprintln(os.Stderr, "→ unlocking the NordPass CLI vault")
		if err := npInteractive("unlock"); err != nil {
			return fmt.Errorf("np unlock: %v", err)
		}
	}
	return nil
}
