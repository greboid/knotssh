package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var (
	hookLocks sync.Map
)

func setupHook(repoPath string) error {
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return err
	}
	hook := filepath.Join(hooksDir, "post-receive")
	if err := os.Remove(hook); err != nil && !os.IsNotExist(err) {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer func() {
		if err := src.Close(); err != nil {
			slog.Warn("failed to close source file", "error", err)
		}
	}()
	dst, err := os.OpenFile(hook, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer func() {
		if err := dst.Close(); err != nil {
			slog.Warn("failed to close destination file", "error", err)
		}
	}()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
}

func cleanupHook(repoPath string) {
	hook := filepath.Join(repoPath, "hooks", "post-receive")
	if err := os.Remove(hook); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove hook", "error", err, "hook", hook)
	}
}
