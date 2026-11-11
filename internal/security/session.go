package security

import (
	"sync"
	"time"
)

type Session struct {
	TokenHash string
	UserID    uint
	Username  string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

func NewSessionManager(ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	m := &SessionManager{sessions: make(map[string]*Session), ttl: ttl}
	go m.cleanup()
	return m
}

func (m *SessionManager) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.mu.Lock()
	m.ttl = ttl
	m.mu.Unlock()
}

func (m *SessionManager) Create(userID uint, username, ip, userAgent string) (*Session, string, error) {
	token, err := RandomToken(32)
	if err != nil {
		return nil, "", err
	}
	csrf, err := RandomToken(24)
	if err != nil {
		return nil, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	s := &Session{
		TokenHash: HashToken(token),
		UserID:    userID,
		Username:  username,
		CSRFToken: csrf,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
		IP:        ip,
		UserAgent: userAgent,
	}
	m.sessions[s.TokenHash] = s
	return s, token, nil
}

func (m *SessionManager) Get(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	key := HashToken(token)
	m.mu.RLock()
	s, ok := m.sessions[key]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(s.ExpiresAt) {
		m.Delete(token)
		return nil, false
	}
	return s, true
}

func (m *SessionManager) Delete(token string) {
	key := HashToken(token)
	m.mu.Lock()
	delete(m.sessions, key)
	m.mu.Unlock()
}

func (m *SessionManager) DeleteUser(userID uint) {
	m.mu.Lock()
	for k, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, k)
		}
	}
	m.mu.Unlock()
}

func (m *SessionManager) DeleteAll() {
	m.mu.Lock()
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()
}

func (m *SessionManager) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for k, s := range m.sessions {
			if now.After(s.ExpiresAt) {
				delete(m.sessions, k)
			}
		}
		m.mu.Unlock()
	}
}

// LoginLimiter provides an in-memory per-key failure limiter. Database-backed
// account locking is implemented in the auth service as a second layer.
type LoginLimiter struct {
	mu       sync.Mutex
	entries  map[string]*limitEntry
	max      int
	window   time.Duration
	lockTime time.Duration
}

type limitEntry struct {
	failures  int
	firstSeen time.Time
	lockedAt  time.Time
}

func NewLoginLimiter(max int, window, lockTime time.Duration) *LoginLimiter {
	if max <= 0 {
		max = 5
	}
	return &LoginLimiter{entries: make(map[string]*limitEntry), max: max, window: window, lockTime: lockTime}
}

func (l *LoginLimiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true
	}
	if !e.lockedAt.IsZero() && time.Since(e.lockedAt) < l.lockTime {
		return false
	}
	if time.Since(e.firstSeen) > l.window {
		delete(l.entries, key)
		return true
	}
	return e.failures < l.max
}

func (l *LoginLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || time.Since(e.firstSeen) > l.window {
		e = &limitEntry{firstSeen: time.Now()}
		l.entries[key] = e
	}
	e.failures++
	if e.failures >= l.max {
		e.lockedAt = time.Now()
	}
}

func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}
