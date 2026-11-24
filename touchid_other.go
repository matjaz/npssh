//go:build !darwin || !cgo

package main

import (
	"errors"
	"log"
	"os"
)

// Non-macOS / non-cgo builds exist only for development and testing:
// NPSSH_TEST_APPROVE=1 approves, anything else denies.
func authenticate(reason string) (bool, error) {
	switch os.Getenv("NPSSH_TEST_APPROVE") {
	case "1":
		log.Printf("[test] auto-approve: %s", reason)
		return true, nil
	case "0":
		log.Printf("[test] auto-deny: %s", reason)
		return false, nil
	}
	return false, errors.New("no user-presence check on this platform (build on macOS with cgo)")
}
