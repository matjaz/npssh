package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// describePeer returns e.g. `ssh git@github.com … ← git push` for the
// process on the other end of the socket.
func describePeer(c net.Conn) string {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return "unknown process"
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return "unknown process"
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) { pid = peerPID(int(fd)) })
	if pid <= 0 {
		return "unknown process"
	}
	cmd, ppid := procInfo(pid)
	desc := fmt.Sprintf("%s (pid %d)", trunc(cmd, 70), pid)
	if ppid > 1 {
		if pcmd, _ := procInfo(ppid); pcmd != "" {
			desc += " ← " + trunc(pcmd, 50)
		}
	}
	return desc
}

func procInfo(pid int) (cmd string, ppid int) {
	out, err := exec.Command("ps", "-o", "ppid=,command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", 0
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) < 2 {
		return "", 0
	}
	ppid, _ = strconv.Atoi(f[0])
	return strings.Join(f[1:], " "), ppid
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
