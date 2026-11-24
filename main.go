// npssh — an SSH agent whose keys live in NordPass, are held only in memory,
// and require Touch ID for every signature.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// version is set at release time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usage = `npssh — SSH agent backed by NordPass, Touch ID per signature

  npssh serve    [--socket P] [--approve-ttl 0]   run the agent (foreground)
  npssh install  [--approve-ttl 0]                install + start as a launchd agent (macOS)
  npssh uninstall                                 stop + remove the launchd agent
  npssh generate <name> [--folder F]              new ed25519 key straight into NordPass (never on disk)
  npssh import   <name> <keyfile> [--folder F]    copy an existing key file into NordPass
  npssh load     [--ttl 8h] [--keep-unlocked]     NordPass → agent memory, then lock the np vault
  npssh list                                      keys currently in the agent
  npssh lock                                      wipe all keys from agent memory
  npssh version

Items are named "SSH <name>"; the list of items to load is ~/.config/npssh/keys.
Point ssh at the socket:  export SSH_AUTH_SOCK=~/.npssh/agent.sock
`

func home(p ...string) string {
	h, _ := os.UserHomeDir()
	return filepath.Join(append([]string{h}, p...)...)
}

func defaultSocket() string {
	if s := os.Getenv("NPSSH_SOCK"); s != "" {
		return s
	}
	return home(".npssh", "agent.sock")
}

func keysFile() string { return home(".config", "npssh", "keys") }

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall()
	case "generate":
		err = cmdGenerate(args)
	case "import":
		err = cmdImport(args)
	case "load":
		err = cmdLoad(args)
	case "list", "ls":
		err = cmdList()
	case "lock":
		err = cmdLock()
	case "version", "--version", "-v":
		fmt.Println("npssh", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "npssh:", err)
		os.Exit(1)
	}
}

// parseInterleaved lets flags appear after positional args (npssh import x f --folder F).
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// ---------- serve ----------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	sock := fs.String("socket", defaultSocket(), "socket path")
	ttl := fs.Duration("approve-ttl", 0, "reuse a Touch ID approval per key for this long (0 = ask every time)")
	fs.Parse(args)

	if err := os.MkdirAll(filepath.Dir(*sock), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Dir(*sock), 0o700)
	if c, err := net.Dial("unix", *sock); err == nil {
		c.Close()
		return fmt.Errorf("an agent is already listening on %s", *sock)
	}
	os.Remove(*sock)

	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", *sock)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	os.Chmod(*sock, 0o600)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; l.Close(); os.Remove(*sock); os.Exit(0) }()

	g := newGuardedAgent(*ttl)
	log.Printf("npssh agent listening on %s (approve-ttl %s)", *sock, *ttl)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			ca := &connAgent{g: g, peer: describePeer(c)}
			_ = agent.ServeAgent(ca, c)
		}(c)
	}
}

// ---------- client helpers ----------

func dialAgent() (agent.ExtendedAgent, func(), error) {
	sock := defaultSocket()
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("agent not running on %s (npssh install, or npssh serve): %v", sock, err)
	}
	return agent.NewClient(c), func() { c.Close() }, nil
}

func cmdList() error {
	a, done, err := dialAgent()
	if err != nil {
		return err
	}
	defer done()
	keys, err := a.List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no keys loaded (npssh load)")
	}
	for _, k := range keys {
		pk, _ := ssh.ParsePublicKey(k.Blob)
		fmt.Printf("%s  %s  %s\n", ssh.FingerprintSHA256(pk), k.Format, k.Comment)
	}
	return nil
}

func cmdLock() error {
	a, done, err := dialAgent()
	if err != nil {
		return err
	}
	defer done()
	if err := a.RemoveAll(); err != nil {
		return err
	}
	fmt.Println("all keys wiped from agent memory")
	return nil
}

// ---------- key list ----------

func readKeyTitles() ([]string, error) {
	f, err := os.Open(keysFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s missing — add NordPass item titles (one per line) or use npssh import/generate", keysFile())
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, s.Err()
}

func addKeyTitle(title string) error {
	existing, _ := readKeyTitles()
	for _, t := range existing {
		if t == title {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(keysFile()), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(keysFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, title)
	return err
}

// ---------- load ----------

func parsePrivate(title string, pemKey []byte) (any, error) {
	k, err := ssh.ParseRawPrivateKey(pemKey)
	var pm *ssh.PassphraseMissingError
	if errors.As(err, &pm) {
		fmt.Fprintf(os.Stderr, "passphrase for %q: ", title)
		pass, perr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if perr != nil {
			return nil, perr
		}
		return ssh.ParseRawPrivateKeyWithPassphrase(pemKey, pass)
	}
	return k, err
}

func cmdLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	ttl := fs.Duration("ttl", 8*time.Hour, "drop keys from agent memory after this long (0 = until lock/restart)")
	keep := fs.Bool("keep-unlocked", false, "don't run `np lock` afterwards")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	titles := pos
	if len(titles) == 0 {
		if titles, err = readKeyTitles(); err != nil {
			return err
		}
	}
	a, done, err := dialAgent()
	if err != nil {
		return err
	}
	defer done()
	if err := npEnsureUnlocked(); err != nil {
		return err
	}

	loaded := 0
	for _, t := range titles {
		pemKey, err := npFetchPrivate(t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", t, err)
			continue
		}
		priv, err := parsePrivate(t, pemKey)
		for i := range pemKey {
			pemKey[i] = 0
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", t, err)
			continue
		}
		if err := a.Add(agent.AddedKey{PrivateKey: priv, Comment: t, LifetimeSecs: uint32(ttl.Seconds())}); err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", t, err)
			continue
		}
		fmt.Printf("✓ %s\n", t)
		loaded++
	}
	if !*keep {
		if err := exec.Command(npBin(), "lock").Run(); err == nil {
			fmt.Println("NordPass CLI vault locked")
		}
	}
	if loaded == 0 {
		return errors.New("no keys loaded")
	}
	return nil
}

// ---------- generate / import ----------

func storeKey(name string, pemKey []byte, folder string) error {
	title := "SSH " + name
	if err := validTitle(title); err != nil {
		return err
	}
	priv, err := parsePrivate(title, pemKey)
	if err != nil {
		return fmt.Errorf("not a usable private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + name

	// Unlock before checking for an existing item: on a locked vault every
	// lookup fails, which used to read as "missing" and create a duplicate.
	if err := npEnsureUnlocked(); err != nil {
		return err
	}
	if n, err := npTitleCount(title); err != nil {
		return err
	} else if n > 0 {
		return fmt.Errorf("NordPass item %q already exists", title)
	}
	if err := npCreate(title, pub, pemKey, folder); err != nil {
		return fmt.Errorf("np item create: %v", err)
	}
	// Read it back and make sure the stored bytes round-trip.
	back, err := npFetchPrivate(title)
	if err != nil {
		return fmt.Errorf("stored, but read-back failed: %v", err)
	}
	if strings.TrimSpace(string(back)) != strings.TrimSpace(string(pemKey)) {
		return fmt.Errorf("stored, but read-back differs — check item %q in NordPass", title)
	}
	if err := addKeyTitle(title); err != nil {
		return err
	}
	fmt.Printf("✓ stored as NordPass item %q (verified) and added to %s\n\npublic key:\n%s\n", title, keysFile(), pub)
	return nil
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	folder := fs.String("folder", "", "NordPass folder")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 {
		return errors.New("usage: npssh generate <name> [--folder F]")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	blk, err := ssh.MarshalPrivateKey(priv, pos[0])
	if err != nil {
		return err
	}
	return storeKey(pos[0], pem.EncodeToMemory(blk), *folder)
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	folder := fs.String("folder", "", "NordPass folder")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 2 {
		return errors.New("usage: npssh import <name> <keyfile> [--folder F]")
	}
	data, err := os.ReadFile(pos[1])
	if err != nil {
		return err
	}
	if err := storeKey(pos[0], data, *folder); err != nil {
		return err
	}
	fmt.Printf("\nAfter `npssh load` + a test login works, remove the file:\n  rm -P %s\n", pos[1])
	return nil
}
