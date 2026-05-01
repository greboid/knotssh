package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type cachedKeys struct {
	keys   []keyEntry
	expiry time.Time
	mu     sync.RWMutex
}

type hookNotifyResult struct {
	Messages []string `json:"messages"`
}

var (
	keyCache   = &cachedKeys{}
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	keyGroup singleflight.Group
)

func (c *cachedKeys) fetch(api string) ([]keyEntry, error) {
	c.mu.RLock()
	if time.Now().Before(c.expiry) {
		keys := c.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	result, err, _ := keyGroup.Do("keys", func() (interface{}, error) {
		resp, err := httpClient.Get(api + "/keys")
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Warn("failed to close response body", "error", err)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("key fetch: unexpected status %d", resp.StatusCode)
		}
		var keys []keyEntry
		if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.keys = keys
		c.expiry = time.Now().Add(10 * time.Second)
		c.mu.Unlock()

		return keys, nil
	})

	if err != nil {
		return nil, err
	}
	return result.([]keyEntry), nil
}

func guardRequest(api, user, repo, gitCmd string) (string, error) {
	u, err := url.Parse(api + "/guard")
	if err != nil {
		slog.Error("invalid API URL", "error", err, "api", api)
		return "", fmt.Errorf("internal server error")
	}
	q := u.Query()
	q.Set("user", user)
	q.Set("repo", repo)
	q.Set("gitCmd", gitCmd)
	u.RawQuery = q.Encode()

	resp, err := httpClient.Get(u.String())
	if err != nil {
		slog.Error("guard request failed", "error", err, "repo", repo, "user", user)
		return "", fmt.Errorf("authorization failed")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close response body", "error", err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("guard response read failed", "error", err, "repo", repo, "user", user)
		return "", fmt.Errorf("authorization failed")
	}
	if resp.StatusCode != http.StatusOK {
		slog.Warn("guard denied access", "status", resp.StatusCode, "repo", repo, "user", user)
		return "", fmt.Errorf("access denied")
	}
	resolved := strings.TrimSpace(string(body))
	if resolved == "" || strings.ContainsRune(resolved, 0) || strings.ContainsRune(resolved, '\n') {
		slog.Error("guard returned invalid path", "path", resolved, "repo", repo, "user", user)
		return "", fmt.Errorf("authorization failed")
	}
	if filepath.IsAbs(resolved) {
		slog.Error("guard returned absolute path", "path", resolved, "repo", repo, "user", user)
		return "", fmt.Errorf("authorization failed")
	}
	cleaned := filepath.Clean(resolved)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		slog.Error("guard returned path with traversal", "path", resolved, "repo", repo, "user", user)
		return "", fmt.Errorf("authorization failed")
	}
	return cleaned, nil
}

func notifyPush(api, did, repoPath string, refsData []byte) {
	req, err := http.NewRequest("POST", api+"/hooks/post-receive", strings.NewReader(string(refsData)))
	if err != nil {
		slog.Error("hook notify failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("X-Git-Dir", repoPath)
	req.Header.Set("X-Git-User-Did", did)

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Error("hook notify failed", "error", err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close response body", "error", err)
		}
	}()

	var result hookNotifyResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err == nil {
		for _, msg := range result.Messages {
			slog.Info("hook message", "message", msg)
		}
	}
}
