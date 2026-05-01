package main

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastUsed atomic.Int64
}

var (
	ipLimiters sync.Map
	limiterMu  sync.RWMutex
)

func getIPLimiter(ip string) *rate.Limiter {
	now := time.Now().Unix()
	if v, ok := ipLimiters.Load(ip); ok {
		entry := v.(*ipLimiter)
		entry.lastUsed.Store(now)
		return entry.limiter
	}

	limiterMu.Lock()
	defer limiterMu.Unlock()

	if v, ok := ipLimiters.Load(ip); ok {
		entry := v.(*ipLimiter)
		entry.lastUsed.Store(now)
		return entry.limiter
	}

	entry := &ipLimiter{
		limiter: rate.NewLimiter(rate.Limit(10), 100),
	}
	entry.lastUsed.Store(now)
	ipLimiters.Store(ip, entry)
	return entry.limiter
}

func cleanupLimiters() {
	for {
		time.Sleep(5 * time.Minute)
		cutoff := time.Now().Add(-10 * time.Minute).Unix()
		ipLimiters.Range(func(key, value interface{}) bool {
			entry := value.(*ipLimiter)
			if entry.lastUsed.Load() < cutoff {
				ipLimiters.Delete(key)
			}
			return true
		})
	}
}
