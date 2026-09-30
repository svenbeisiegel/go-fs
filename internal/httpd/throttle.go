package httpd

import (
	"sort"
	"sync"
	"time"
)

// The login lock is what stands between an address and guessing passwords at
// full speed. The delay on a wrong password slows one request; it does nothing
// about a hundred sent at once, and each of them holds a connection slot for
// the whole delay. So the wrong passwords are counted per client address, and
// an address that has sent http.loginAttempts of them inside
// http.loginLockout seconds is refused for that long, at once and without
// looking at what it sent.
//
// Only a wrong password counts: a header that cannot be read, a nonce another
// server issued or one that has merely aged out is not a guess and cannot
// succeed anyway. A right password clears the count. A session token is never
// counted or refused: it is not a guess either, and someone behind the same
// address as a guesser keeps their login.
//
// The count is a snapshot per request: a burst of requests that arrive
// together can all pass the check before the first is counted. Each of them
// still pays the delay and a connection slot, so the burst is bounded by
// http.maxConnections, and every request after it is refused.

const (
	// evictAbove is the size from which the expired records are swept, at most
	// once per sweepEvery, before a new one is added: the map is tidied as it
	// is used rather than on a timer of its own, and a flood of new addresses
	// does not pay for a sweep on every one of them.
	evictAbove = 1024
	sweepEvery = time.Minute
	// maxTracked bounds the map whatever the traffic: a flood of addresses
	// that each fail once is answered by forgetting the oldest of them, a
	// batch at a time so that the flood does not pay for a search on every
	// request either.
	maxTracked = 65536
	shedBatch  = maxTracked / 8
)

// loginTracker counts the wrong passwords per client address.
type loginTracker struct {
	mu      sync.Mutex
	clients map[string]*loginRecord
	swept   time.Time
	// now is time.Now; a test replaces it to move time without waiting.
	now func() time.Time
}

// loginRecord is one address: the failures inside the current window, when
// that window opened, and until when the address is refused.
type loginRecord struct {
	failures    int
	since       time.Time
	lockedUntil time.Time
}

func newLoginTracker() *loginTracker {
	return &loginTracker{clients: make(map[string]*loginRecord), now: time.Now}
}

// locked reports whether an address is refused right now, and for how much
// longer.
func (t *loginTracker) locked(address string) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	record, ok := t.clients[address]
	if !ok {
		return 0, false
	}
	remaining := record.lockedUntil.Sub(t.now())
	if remaining <= 0 {
		return 0, false
	}
	return remaining, true
}

// failed records a wrong password from an address and reports whether that
// was the one that locked it. attempts is http.loginAttempts, 0 for a lock
// that is off; lockout is the window and the lock length both.
func (t *loginTracker) failed(address string, attempts int, lockout time.Duration) bool {
	if attempts <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	record, ok := t.clients[address]
	if !ok {
		if len(t.clients) >= evictAbove {
			t.evict(now, lockout)
		}
		record = &loginRecord{since: now}
		t.clients[address] = record
	}
	if now.After(record.since.Add(lockout)) {
		// the window has closed: what was counted in it is forgotten
		record.failures = 0
		record.since = now
	}
	record.failures++
	if record.failures < attempts {
		return false
	}
	record.failures = 0
	record.since = now
	record.lockedUntil = now.Add(lockout)
	return true
}

// clear forgets an address, which is what a right password does.
func (t *loginTracker) clear(address string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.clients, address)
}

// evict drops every record that says nothing any more: its lock has passed
// and its window has closed. It does so at most once per sweepEvery, unless
// the map is full; then, if the sweep was not enough, the records that have
// been quiet longest go too, shedBatch of them at once. It runs under the
// lock.
func (t *loginTracker) evict(now time.Time, lockout time.Duration) {
	full := len(t.clients) >= maxTracked
	if !full && now.Sub(t.swept) < sweepEvery {
		return
	}
	t.swept = now
	for address, record := range t.clients {
		if !now.Before(record.lockedUntil) && now.After(record.since.Add(lockout)) {
			delete(t.clients, address)
		}
	}
	if len(t.clients) < maxTracked {
		return
	}
	type aged struct {
		address string
		since   time.Time
	}
	all := make([]aged, 0, len(t.clients))
	for address, record := range t.clients {
		all = append(all, aged{address, record.since})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].since.Before(all[j].since) })
	for _, old := range all[:shedBatch] {
		delete(t.clients, old.address)
	}
}

// size is how many addresses are tracked, for the tests.
func (t *loginTracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.clients)
}
