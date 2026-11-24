package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const label = "dev.npssh.agent"

func plistPath() string { return home("Library", "LaunchAgents", label+".plist") }

func cmdInstall(args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("install is macOS-only; run `npssh serve` under your own supervisor")
	}
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	ttl := fs.Duration("approve-ttl", 0, "reuse a Touch ID approval per key for this long (0 = ask every time)")
	fs.Parse(args)

	exe, err := stableExecutable()
	if err != nil {
		return err
	}
	logf := home(".npssh", "agent.log")
	os.MkdirAll(filepath.Dir(logf), 0o700)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>serve</string>
    <string>--socket</string><string>%s</string>
    <string>--approve-ttl</string><string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, label, exe, defaultSocket(), ttl.String(), logf, logf)

	os.MkdirAll(filepath.Dir(plistPath()), 0o755)
	if err := os.WriteFile(plistPath(), []byte(plist), 0o644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	exec.Command("launchctl", "bootout", domain+"/"+label).Run() // ignore: may not be loaded
	if out, err := exec.Command("launchctl", "bootstrap", domain, plistPath()).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
	}
	fmt.Printf(`✓ launchd agent %s running (log: %s)

Add to ~/.zshrc:
  export SSH_AUTH_SOCK=%s

Add to the top of ~/.ssh/config:
  Host *
    IdentityAgent %s

Then:  npssh generate github   (or: npssh import github ~/.ssh/id_ed25519)
       npssh load
`, label, logf, defaultSocket(), defaultSocket())
	return nil
}

// stableExecutable returns a path to this binary that survives upgrades.
// Homebrew's versioned Cellar path (deleted by `brew upgrade`) is swapped for
// its opt/ symlink, which always points at the installed version.
func stableExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return stablePath(exe), nil
}

func stablePath(exe string) string {
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	// <prefix>/Cellar/npssh/<version>/bin/npssh → <prefix>/opt/npssh/bin/npssh
	if i := strings.Index(exe, "/Cellar/npssh/"); i >= 0 {
		opt := exe[:i] + "/opt/npssh/bin/npssh"
		if r, err := filepath.EvalSymlinks(opt); err == nil && r == exe {
			return opt
		}
	}
	return exe
}

func cmdUninstall() error {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	exec.Command("launchctl", "bootout", domain+"/"+label).Run()
	if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	os.Remove(defaultSocket())
	fmt.Println("✓ removed launchd agent", label)
	return nil
}
