package request

import (
	"context"
	"sync"
	"time"
)

// Memory is the reference ReplayStore: one process, in memory. It is correct for exactly one
// verifier process, and its RESTART POLICY is what makes it correct across a restart at all
// (ADR 0010 §5: losing accepted identifiers reopens old proofs).
//
// A proof is acceptable from entry.From (created − δ). A process started at Start cannot know
// what an earlier process accepted, so Memory admits only proofs whose window opened at or after
// Start, and answers Unavailable for anything older — waiting out, rather than guessing about,
// the proofs a previous incarnation could have seen. A deployment with more than one verifier,
// or that cannot afford the wait, supplies a shared store with the same InsertIfAbsent contract.
//
// An identifier stays remembered until Sweep removes it after its Until; retaining one longer is
// always safe, so nothing here compares against a clock of its own.
type Memory struct {
	Start time.Time // when this incarnation began

	mu   sync.Mutex
	seen map[ReplayKey]time.Time
}

// NewMemory is a Memory whose incarnation begins at start.
func NewMemory(start time.Time) *Memory {
	return &Memory{Start: start}
}

// InsertIfAbsent implements ReplayStore.
func (m *Memory) InsertIfAbsent(_ context.Context, e ReplayEntry) Outcome {
	if e.From.Before(m.Start) {
		return Unavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[ReplayKey]time.Time{}
	}
	if _, ok := m.seen[e.Key]; ok {
		return AlreadyPresent
	}
	m.seen[e.Key] = e.Until
	return Inserted
}

// Sweep forgets every identifier whose Until is not after now and returns how many. Optional and
// caller-driven, like the login handler's: nothing here starts a goroutine.
func (m *Memory) Sweep(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, until := range m.seen {
		if !now.Before(until) {
			delete(m.seen, k)
			n++
		}
	}
	return n
}
