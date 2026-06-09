package tcp

import (
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestStateMachine_ValidTransitions(t *testing.T) {
	log := zaptest.NewLogger(t)
	sm := NewStateMachine(StateClosed, log)

	var lastFrom, lastTo State
	sm.SetOnTransition(func(from, to State) {
		lastFrom = from
		lastTo = to
	})

	// CLOSED -> SYN_SENT
	if err := sm.Transition(StateSynSent); err != nil {
		t.Fatalf("expected transition to succeed: %v", err)
	}
	if sm.Current() != StateSynSent {
		t.Errorf("expected state to be SYN_SENT, got %s", sm.Current())
	}
	if lastFrom != StateClosed || lastTo != StateSynSent {
		t.Errorf("expected callback with CLOSED -> SYN_SENT")
	}

	// SYN_SENT -> ESTABLISHED
	if err := sm.Transition(StateEstablished); err != nil {
		t.Fatalf("expected transition to succeed: %v", err)
	}
	if !sm.Is(StateEstablished) {
		t.Errorf("expected Is(ESTABLISHED) to be true")
	}
}

func TestStateMachine_InvalidTransition(t *testing.T) {
	log := zaptest.NewLogger(t)
	sm := NewStateMachine(StateClosed, log)

	// CLOSED -> ESTABLISHED is invalid
	err := sm.Transition(StateEstablished)
	if err == nil {
		t.Fatalf("expected transition to fail")
	}

	if sm.Current() != StateClosed {
		t.Errorf("expected state to remain CLOSED, got %s", sm.Current())
	}
}

func TestStateMachine_StateStrings(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "CLOSED"},
		{StateListen, "LISTEN"},
		{StateSynSent, "SYN_SENT"},
		{StateSynReceived, "SYN_RECEIVED"},
		{StateEstablished, "ESTABLISHED"},
		{StateFinWait1, "FIN_WAIT_1"},
		{StateFinWait2, "FIN_WAIT_2"},
		{StateCloseWait, "CLOSE_WAIT"},
		{StateClosing, "CLOSING"},
		{StateLastAck, "LAST_ACK"},
		{StateTimeWait, "TIME_WAIT"},
		{State(99), "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("State(%d).String() = %v, want %v", tt.state, got, tt.expected)
		}
	}
}
