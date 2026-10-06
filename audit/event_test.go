package audit

import (
	"strings"
	"testing"
	"time"
)

func TestEventValidate(t *testing.T) {
	event := Event{ID: "event-1", Timestamp: time.Now(), Actor: "user:1", Action: "door.open", Resource: "door:1", Result: ResultSuccess}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	event.Result = "maybe"
	if err := event.Validate(); err == nil {
		t.Fatal("invalid result accepted")
	}
}

func TestEventRejectsOversizedOrInvalidEnvelope(t *testing.T) {
	base := Event{ID: "event-1", Timestamp: time.Now(), Actor: "user:1", Action: "door.open", Resource: "door:1", Result: ResultSuccess}
	tests := []Event{
		func() Event { event := base; event.ID = strings.Repeat("i", MaxIDBytes+1); return event }(),
		func() Event { event := base; event.Actor = strings.Repeat("a", MaxActorBytes+1); return event }(),
		func() Event { event := base; event.Action = strings.Repeat("x", MaxActionBytes+1); return event }(),
		func() Event { event := base; event.Resource = strings.Repeat("r", MaxResourceBytes+1); return event }(),
		func() Event {
			event := base
			event.CorrelationID = strings.Repeat("c", MaxCorrelationIDBytes+1)
			return event
		}(),
		func() Event { event := base; event.Actor = string([]byte{0xff}); return event }(),
	}
	for _, event := range tests {
		if err := event.Validate(); err == nil {
			t.Fatal("invalid audit envelope accepted")
		}
	}
}

func TestEventRejectsOversizedMetadata(t *testing.T) {
	event := Event{
		ID: "event-1", Timestamp: time.Now(), Actor: "user:1", Action: "login",
		Resource: "session:1", Result: ResultSuccess,
		Metadata: map[string]any{"note": strings.Repeat("x", MaxMetadataBytes)},
	}
	if err := event.Validate(); err == nil {
		t.Fatal("oversized audit metadata accepted")
	}
}

func TestEventRejectsSensitiveNestedMetadata(t *testing.T) {
	event := Event{ID: "event-1", Timestamp: time.Now(), Actor: "user:1", Action: "login", Resource: "session:1", Result: ResultSuccess, Metadata: map[string]any{"details": map[string]string{"access_token": "private"}}}
	if err := event.Validate(); err == nil {
		t.Fatal("sensitive metadata accepted")
	}
}
