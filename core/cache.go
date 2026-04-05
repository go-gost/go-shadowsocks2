package core

import (
	"sync"
	"time"
)

// CacheItem is the interface that cache values must implement to be checked for expiration.
type CacheItem interface {
	LastUsed() time.Time
}

// SessionCache provides a thread-safe generic cache with background TTL eviction.
type SessionCache[K comparable, V CacheItem] struct {
	items   map[K]V
	timeout time.Duration
	stop    chan struct{}
	mu      sync.RWMutex
	onEvict func(K, V)
}

// NewSessionCache creates a new generic SessionCache.
func NewSessionCache[K comparable, V CacheItem](timeout time.Duration, onEvict func(K, V)) *SessionCache[K, V] {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	c := &SessionCache[K, V]{
		items:   make(map[K]V),
		timeout: timeout,
		stop:    make(chan struct{}),
		onEvict: onEvict,
	}
	go c.cleanupLoop()
	return c
}

// Get retrieves an item by key.
func (c *SessionCache[K, V]) Get(key K) (V, bool) {
	var zero V
	now := time.Now()

	c.mu.RLock()
	v, exists := c.items[key]
	if !exists {
		c.mu.RUnlock()
		return zero, false
	}
	expired := now.Sub(v.LastUsed()) > c.timeout
	c.mu.RUnlock()

	if !expired {
		return v, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	v, exists = c.items[key]
	if !exists {
		return zero, false
	}
	if now.Sub(v.LastUsed()) <= c.timeout {
		return v, true
	}

	delete(c.items, key)
	if c.onEvict != nil {
		c.onEvict(key, v)
	}

	return zero, false
}

// Put adds or updates an item.
func (c *SessionCache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = value
}

// Delete removes an item by key.
func (c *SessionCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, exists := c.items[key]; exists {
		delete(c.items, key)
		if c.onEvict != nil {
			c.onEvict(key, v)
		}
	}
}

// cleanupLoop runs in the background to remove expired items.
func (c *SessionCache[K, V]) cleanupLoop() {
	ticker := time.NewTicker(c.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup iterates and deletes expired items.
func (c *SessionCache[K, V]) cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range c.items {
		if now.Sub(v.LastUsed()) > c.timeout {
			delete(c.items, k)
			if c.onEvict != nil {
				c.onEvict(k, v)
			}
		}
	}
}

// Close stops the cleanup loop and clears the cache.
func (c *SessionCache[K, V]) Close() error {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.items {
		if c.onEvict != nil {
			c.onEvict(k, v)
		}
	}
	c.items = make(map[K]V)
	return nil
}
