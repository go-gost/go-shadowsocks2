package shadowaead2022

import (
	"sync"
	"time"
)

// SaltFilter implements time-based salt filtering per SIP022 specification
// Salts are stored for exactly 60 seconds as required by the spec
type SaltFilter struct {
	salts           map[string]int64 // salt -> expiry timestamp
	mutex           sync.RWMutex
	stopCleanup     chan struct{}
	cleanupInterval time.Duration
}

// NewSaltFilter creates a new SIP022-compliant salt filter
func NewSaltFilter() *SaltFilter {
	sf := &SaltFilter{
		salts:           make(map[string]int64),
		stopCleanup:     make(chan struct{}),
		cleanupInterval: 10 * time.Second, // cleanup every 10 seconds
	}

	// Start cleanup routine
	go sf.cleanupRoutine()

	return sf
}

// Check tests if salt exists, and if not, adds it. Returns true if salt was already present.
func (sf *SaltFilter) Check(salt []byte) bool {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	saltStr := string(salt)
	expiry, exists := sf.salts[saltStr]
	now := time.Now().Unix()

	if !exists {
		sf.salts[saltStr] = now + 60
		return true
	}

	if now > expiry {
		// treat salt as new salt
		sf.salts[saltStr] = now + 60
		return true
	}

	return false
}

// cleanupRoutine removes expired salts periodically
func (sf *SaltFilter) cleanupRoutine() {
	ticker := time.NewTicker(sf.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sf.cleanupExpired()
		case <-sf.stopCleanup:
			return
		}
	}
}

// cleanup removes expired salts from the filter
func (sf *SaltFilter) cleanupExpired() {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	now := time.Now().Unix()
	for salt, expiry := range sf.salts {
		if now > expiry {
			delete(sf.salts, salt)
		}
	}
}

// Close stops the cleanup routine
func (sf *SaltFilter) Close() {
	close(sf.stopCleanup)
}

// Global SIP022 salt filter instance
var saltFilter *SaltFilter
var initSaltFilterOnce sync.Once

// GetSaltFilter returns the global SIP022 salt filter instance
func GetSaltFilter() *SaltFilter {
	initSaltFilterOnce.Do(func() {
		saltFilter = NewSaltFilter()
	})
	return saltFilter
}

// CheckSalt checks if a salt is repeated using SIP022 time-based filtering
func CheckSalt(salt []byte) bool {
	filter := GetSaltFilter()

	return filter.Check(salt)
}
