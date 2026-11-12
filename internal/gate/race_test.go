package gate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

const parallel = 40

func TestConcurrentWrongGuessesAreCheckedAtMostMaxAttemptsTimes(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	wrong := "00000"
	if wrong == e.ntf.last().PendingOTP {
		wrong = "11111"
	}
	var wrongCode atomic.Int32
	var wg sync.WaitGroup
	for range parallel {
		wg.Go(func() {
			if _, err := e.gate.Verify(ctx, e.key, wrong); errors.Is(err, ErrWrongCode) {
				wrongCode.Add(1)
			}
		})
	}
	wg.Wait()
	if n := wrongCode.Load(); n > 2 {
		t.Fatalf("%d parallel guesses were answered as wrong codes; at most MaxAttempts-1 (2) may be", n)
	}
	ch, err := e.st.ChallengeByID(ctx, e.ntf.last().ID)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Attempts != 3 {
		t.Fatalf("attempts %d, want 3", ch.Attempts)
	}
}

func TestConcurrentApproveAndDenyResolveOnce(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.gate.Block(ctx, e.key, "echo__echo"); err != nil {
		t.Fatal(err)
	}
	id := e.ntf.last().ID
	sig := e.gate.sig(id)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range parallel {
		wg.Go(func() {
			resolve := e.gate.Approve
			if i%2 == 1 {
				resolve = e.gate.Deny
			}
			if resolve(ctx, id, sig) == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if n := ok.Load(); n != 1 {
		t.Fatalf("%d approve/deny calls succeeded on one challenge, want exactly 1", n)
	}
}
