package tcp

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// State represents the state of a TCP connection.
type State uint8

const (
	StateClosed State = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateClosing
	StateLastAck
	StateTimeWait
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECEIVED"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN_WAIT_1"
	case StateFinWait2:
		return "FIN_WAIT_2"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateClosing:
		return "CLOSING"
	case StateLastAck:
		return "LAST_ACK"
	case StateTimeWait:
		return "TIME_WAIT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// validTransitions defines all the valid state transitions in TCP.
var validTransitions = map[State][]State{
	StateClosed: {
		StateListen,  // Passive open
		StateSynSent, // Active open
	},
	StateListen: {
		StateSynReceived, // Receive SYN, send SYN-ACK
		StateSynSent,     // Send SYN
		StateClosed,      // Close
	},
	StateSynSent: {
		StateSynReceived, // Receive SYN, send ACK
		StateEstablished, // Receive SYN-ACK, send ACK
		StateClosed,      // Close
	},
	StateSynReceived: {
		StateEstablished, // Receive ACK
		StateFinWait1,    // Close
		StateClosed,      // Reset or Timeout
	},
	StateEstablished: {
		StateFinWait1,  // Close
		StateCloseWait, // Receive FIN
		StateClosed,    // Reset
	},
	StateFinWait1: {
		StateFinWait2, // Receive ACK for FIN
		StateClosing,  // Receive FIN
		StateTimeWait, // Receive FIN+ACK
		StateClosed,   // Reset or timeout
	},
	StateFinWait2: {
		StateTimeWait, // Receive FIN
		StateClosed,   // Reset or timeout
	},
	StateCloseWait: {
		StateLastAck, // Close
		StateClosed,  // Reset
	},
	StateClosing: {
		StateTimeWait, // Receive ACK for FIN
		StateClosed,   // Reset
	},
	StateLastAck: {
		StateClosed, // Receive ACK for FIN
	},
	StateTimeWait: {
		StateClosed, // Timeout (2MSL)
	},
}

// StateMachine manages the state of a TCP connection.
type StateMachine struct {
	current      State
	mu           sync.RWMutex
	log          *zap.Logger
	onTransition func(from, to State)
}

// NewStateMachine creates a new TCP StateMachine.
func NewStateMachine(initial State, log *zap.Logger) *StateMachine {
	return &StateMachine{
		current: initial,
		log:     log,
	}
}

// SetOnTransition sets an optional callback triggered on valid state transitions.
func (sm *StateMachine) SetOnTransition(cb func(from, to State)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onTransition = cb
}

// Transition attempts to transition the state machine to the new state.
// Validates, executes, logs, and triggers the callback if configured.
func (sm *StateMachine) Transition(to State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	from := sm.current
	valid := false

	// Validate transition
	allowed := validTransitions[from]
	for _, state := range allowed {
		if state == to {
			valid = true
			break
		}
	}

	if !valid {
		if sm.log != nil {
			sm.log.Warn("Invalid state transition attempted",
				zap.String("from", from.String()),
				zap.String("to", to.String()),
			)
		}
		return fmt.Errorf("invalid state transition: %s -> %s", from, to)
	}

	// Apply transition
	sm.current = to

	if sm.log != nil {
		sm.log.Debug("State transitioned",
			zap.String("from", from.String()),
			zap.String("to", to.String()),
		)
	}

	// Call callback if configured
	if sm.onTransition != nil {
		sm.onTransition(from, to)
	}

	return nil
}

// Current returns the current state.
func (sm *StateMachine) Current() State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current
}

// Is returns true if the current state matches the provided state.
func (sm *StateMachine) Is(s State) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current == s
}
