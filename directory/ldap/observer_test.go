package ldap

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type observationRecorder struct {
	mu           sync.Mutex
	observations []LookupObservation
}

func (r *observationRecorder) ObserveLDAPLookup(observation LookupObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observations = append(r.observations, observation)
}

func (r *observationRecorder) one(t *testing.T) LookupObservation {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.observations) != 1 {
		t.Fatalf("got %d observations, want one", len(r.observations))
	}
	return r.observations[0]
}

func TestLookupObserverUsesBoundedOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		outcome LookupOutcome
	}{{"success", 1, OutcomeSuccess}, {"missing", 0, OutcomeNotFound}, {"ambiguous", 2, OutcomeAmbiguous}} {
		t.Run(tc.name, func(t *testing.T) {
			reader, closeFixture := protocolFixture(t, tc.count, false)
			defer closeFixture()
			recorder := &observationRecorder{}
			reader.config.Observer = recorder
			_, _ = reader.GetUser(context.Background(), "alice")
			observation := recorder.one(t)
			if observation.Outcome != tc.outcome || observation.Stage != StageResult || observation.Duration < 0 {
				t.Fatalf("unexpected observation: %+v", observation)
			}
		})
	}
}

func TestLookupObserverInputCancellationAndPanicIsolation(t *testing.T) {
	config := testConfig("ldaps://127.0.0.1:1")
	recorder := &observationRecorder{}
	config.Observer = recorder
	reader, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetUser(context.Background(), " "); err == nil {
		t.Fatal("invalid input accepted")
	}
	if got := recorder.one(t); got.Outcome != OutcomeInvalidInput || got.Stage != StageValidation {
		t.Fatalf("got %+v", got)
	}

	config.Observer = ObserverFunc(func(LookupObservation) { panic("synthetic observer panic") })
	reader, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.GetUser(ctx, "alice"); err == nil {
		t.Fatal("canceled lookup succeeded")
	}
}

func TestObserverFormattingCannotExposeClosureState(t *testing.T) {
	secret := "synthetic-secret-marker"
	config := testConfig("ldaps://127.0.0.1:636")
	config.Observer = ObserverFunc(func(LookupObservation) { _ = secret })
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, config), secret) {
			t.Fatal("observer closure state exposed by config formatting")
		}
	}
}
