package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
	"golang.org/x/crypto/ssh"
)

var (
	flagAPI     = flag.String("knot-api", "http://knot:5444", "Base URL of the Knot API")
	flagGitDir  = flag.String("git-dir", "/home/git", "Root directory for bare git repositories")
	flagAddr    = flag.String("ssh-addr", ":22", "Listen address for the SSH server")
	flagHostKey = flag.String("host-key-file", "/keys/host_key", "Path to SSH host key")
)

func main() {
	envflag.Parse()
	slogflags.Logger(slogflags.WithSetDefault(true))

	if os.Getenv("KNOT_HOOK") != "" {
		outFile := os.Getenv("KNOT_HOOK")
		cleanOut := filepath.Clean(outFile)
		tempDir := filepath.Clean(os.TempDir())
		if !strings.HasPrefix(cleanOut+string(filepath.Separator), tempDir+string(filepath.Separator)) {
			slog.Error("hook path outside temp directory", "path", outFile, "tempDir", tempDir)
			os.Exit(1)
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(1)
		}
		f, err := os.OpenFile(cleanOut, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			slog.Error("failed to open hook file", "error", err, "file", outFile)
			os.Exit(1)
		}
		defer func() {
			if err := f.Close(); err != nil {
				slog.Warn("failed to close hook file", "error", err)
			}
		}()
		if _, err := f.Write(data); err != nil {
			slog.Error("failed to write hook data", "error", err, "file", outFile)
			os.Exit(1)
		}
		os.Exit(0)
	}

	api := *flagAPI
	gitDir := *flagGitDir
	addr := *flagAddr
	hostKeyFile := *flagHostKey
	motdPath := filepath.Join(gitDir, "motd")

	signer, err := loadOrGenerateHostKey(hostKeyFile)
	if err != nil {
		slog.Error("host key load failed", "error", err)
		os.Exit(1)
	}

	config := &ssh.ServerConfig{
		MaxAuthTries: 3,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keys, err := keyCache.fetch(api)
			if err != nil {
				slog.Error("key fetch failed", "error", err, "remote", conn.RemoteAddr())
				return nil, fmt.Errorf("authentication failed")
			}
			for _, entry := range keys {
				parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.Key))
				if err != nil {
					continue
				}
				if string(key.Marshal()) == string(parsed.Marshal()) {
					return &ssh.Permissions{
						Extensions: map[string]string{
							"did": entry.DID,
						},
					}, nil
				}
			}
			return nil, fmt.Errorf("permission denied")
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}

	var (
		conns      sync.WaitGroup
		shutdownCh = make(chan struct{})
	)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		slog.Info("shutting down")
		close(shutdownCh)
		if err := listener.Close(); err != nil {
			slog.Warn("failed to close listener", "error", err)
		}
	}()

	slog.Info("listening", "address", addr)

	go cleanupLimiters()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-shutdownCh:
				conns.Wait()
				slog.Info("shutdown complete")
				return
			default:
				slog.Error("accept failed", "error", err)
			}
			continue
		}

		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			slog.Warn("failed to parse remote address", "error", err, "addr", conn.RemoteAddr().String())
			if err := conn.Close(); err != nil {
				slog.Warn("failed to close connection", "error", err)
			}
			continue
		}

		if !getIPLimiter(ip).Allow() {
			slog.Warn("rate limit exceeded, rejecting", "ip", ip)
			if err := conn.Close(); err != nil {
				slog.Warn("failed to close connection", "error", err)
			}
			continue
		}

		conns.Add(1)
		go func() {
			defer conns.Done()
			handleConn(conn, config, api, gitDir, motdPath)
		}()
	}
}
