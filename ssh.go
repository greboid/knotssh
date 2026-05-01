package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func handleConn(netConn net.Conn, config *ssh.ServerConfig, api, gitDir, motdPath string) {
	defer func() {
		if err := netConn.Close(); err != nil {
			slog.Warn("failed to close connection", "error", err)
		}
	}()
	if tcpConn, ok := netConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			slog.Warn("failed to set keepalive", "error", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			slog.Warn("failed to set keepalive period", "error", err)
		}
	}
	conn, chans, reqs, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Warn("failed to close SSH connection", "error", err)
		}
	}()

	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			if err := ch.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
				slog.Warn("failed to reject channel", "error", err)
			}
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go handleSession(channel, reqs, conn, api, gitDir, motdPath)
	}
}

func handleSession(channel ssh.Channel, reqs <-chan *ssh.Request, conn *ssh.ServerConn, api, gitDir, motdPath string) {
	defer func() {
		if err := channel.Close(); err != nil {
			slog.Warn("failed to close channel", "error", err)
		}
	}()

	did := conn.Permissions.Extensions["did"]

	idle := time.NewTimer(5 * time.Minute)
	defer idle.Stop()

	for {
		select {
		case <-idle.C:
			if _, err := io.WriteString(channel.Stderr(), "connection timed out\n"); err != nil {
				slog.Warn("failed to write timeout message", "error", err)
			}
			if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
				slog.Warn("failed to send exit status", "error", err)
			}
			return
		case req, ok := <-reqs:
			if !ok {
				return
			}
			idle.Reset(5 * time.Minute)
			if req.Type != "exec" {
				if err := req.Reply(false, nil); err != nil {
					slog.Warn("failed to reply to request", "error", err)
				}
				continue
			}

			var payload struct{ Value string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Warn("failed to unmarshal exec payload", "error", err)
				if err := req.Reply(false, nil); err != nil {
					slog.Warn("failed to reply to request", "error", err)
				}
				return
			}
			if err := req.Reply(true, nil); err != nil {
				slog.Warn("failed to reply to exec request", "error", err)
			}

			parts := strings.Fields(payload.Value)
			if len(parts) < 2 {
				if _, err := io.WriteString(channel.Stderr(), "access denied: no command\n"); err != nil {
					slog.Warn("failed to write error message", "error", err)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}
				return
			}

			gitCmd := parts[0]
			repoPath := parts[1]

			switch gitCmd {
			case "git-receive-pack", "git-upload-pack", "git-upload-archive":
			default:
				if _, err := io.WriteString(channel.Stderr(), "access denied: invalid git command\n"); err != nil {
					slog.Warn("failed to write error message", "error", err)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}
				return
			}

			qualified, err := guardRequest(api, did, repoPath, gitCmd)
			if err != nil {
				if _, err := io.WriteString(channel.Stderr(), "access denied\n"); err != nil {
					slog.Warn("failed to write error message", "error", err)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}
				return
			}

			fullPath := filepath.Join(gitDir, qualified)
			gitDirClean := filepath.Clean(gitDir)
			fullPathClean := filepath.Clean(fullPath)
			rel, err := filepath.Rel(gitDirClean, fullPathClean)
			if err != nil {
				slog.Warn("path validation failed", "error", err, "path", fullPath, "gitdir", gitDir, "user", did)
				if _, err := io.WriteString(channel.Stderr(), "access denied\n"); err != nil {
					slog.Warn("failed to write error message", "error", err)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}
				return
			}
			if rel == ".." || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				slog.Warn("path traversal attempt", "path", fullPath, "gitdir", gitDir, "user", did)
				if _, err := io.WriteString(channel.Stderr(), "access denied\n"); err != nil {
					slog.Warn("failed to write error message", "error", err)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}
				return
			}

			motd := loadMotd(motdPath)
			if gitCmd == "git-upload-pack" {
				if _, err := channel.Stderr().Write([]byte{0x02}); err != nil {
					slog.Warn("failed to write git protocol byte", "error", err)
				}
			}
			if _, err := io.WriteString(channel.Stderr(), motd); err != nil {
				slog.Warn("failed to write MOTD", "error", err)
			}

			remoteIP, remotePort, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				slog.Warn("failed to parse remote address", "error", err, "addr", conn.RemoteAddr().String())
				remoteIP, remotePort = "unknown", "unknown"
			}
			localIP, localPort, err := net.SplitHostPort(conn.LocalAddr().String())
			if err != nil {
				slog.Warn("failed to parse local address", "error", err, "addr", conn.LocalAddr().String())
				localIP, localPort = "unknown", "unknown"
			}

			cmdEnv := []string{
				"PATH=/usr/local/bin:/usr/bin:/bin",
				"HOME=/home/nonroot",
				"GIT_USER_DID=" + did,
				"GIT_USER_HANDLE=",
				"SSH_CONNECTION=" + remoteIP + " " + remotePort + " " + localIP + " " + localPort,
				"SSH_ORIGINAL_COMMAND=" + gitCmd + " " + repoPath,
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0=safe.directory",
				"GIT_CONFIG_VALUE_0=*",
			}

			idle.Stop()

			if gitCmd == "git-receive-pack" {
				value, _ := hookLocks.LoadOrStore(fullPath, &sync.Mutex{})
				mu := value.(*sync.Mutex)
				mu.Lock()

				tmpFile, err := os.CreateTemp("", "hook-*")
				if err != nil {
					slog.Error("hook temp file creation failed", "error", err, "repo", fullPath)
					mu.Unlock()
					if _, err := io.WriteString(channel.Stderr(), "hook setup failed\n"); err != nil {
						slog.Warn("failed to write error message", "error", err)
					}
					if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
						slog.Warn("failed to send exit status", "error", err)
					}
					return
				}
				tmpFileName := tmpFile.Name()

				if err := setupHook(fullPath); err != nil {
					slog.Error("hook setup failed", "error", err, "repo", fullPath)
					if err := tmpFile.Close(); err != nil {
						slog.Warn("failed to close temp file", "error", err, "file", tmpFileName)
					}
					if err := os.Remove(tmpFileName); err != nil && !os.IsNotExist(err) {
						slog.Warn("failed to remove temp file", "error", err, "file", tmpFileName)
					}
					mu.Unlock()
					if _, err := io.WriteString(channel.Stderr(), "hook setup failed\n"); err != nil {
						slog.Warn("failed to write error message", "error", err)
					}
					if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1})); err != nil {
						slog.Warn("failed to send exit status", "error", err)
					}
					return
				}

				cmdEnv = append(cmdEnv, "KNOT_HOOK="+tmpFileName)

				c := exec.Command(gitCmd, fullPath)
				c.Stdin = channel
				c.Stdout = channel
				c.Stderr = channel.Stderr()
				c.Env = cmdEnv
				runErr := c.Run()

				if _, err := tmpFile.Seek(0, 0); err == nil {
					data, err := io.ReadAll(tmpFile)
					if err != nil {
						slog.Warn("failed to read hook data", "error", err, "file", tmpFileName)
					} else if len(data) > 0 {
						notifyPush(api, did, fullPath, data)
					}
				}

				exitCode := 0
				if runErr != nil {
					var exitErr *exec.ExitError
					if errors.As(runErr, &exitErr) {
						exitCode = exitErr.ExitCode()
					}
				}
				if exitCode == 0 {
					cleanupHook(fullPath)
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)})); err != nil {
					slog.Warn("failed to send exit status", "error", err)
				}

				if err := tmpFile.Close(); err != nil {
					slog.Warn("failed to close temp file", "error", err, "file", tmpFileName)
				}
				if err := os.Remove(tmpFileName); err != nil && !os.IsNotExist(err) {
					slog.Warn("failed to remove temp file", "error", err, "file", tmpFileName)
				}
				mu.Unlock()
				return
			}

			c := exec.Command(gitCmd, fullPath)
			c.Stdin = channel
			c.Stdout = channel
			c.Stderr = channel.Stderr()
			c.Env = cmdEnv
			exitCode := 0
			if err := c.Run(); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = exitErr.ExitCode()
				}
			}
			if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)})); err != nil {
				slog.Warn("failed to send exit status", "error", err)
			}
			return
		}
	}
}
