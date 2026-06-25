package tcp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// ConnKey uniquely identifies a TCP connection.
type ConnKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

// Listener represents a TCP listener (placeholder for future phases).
type Listener struct {
	Port uint16
}

// ConnectionTable manages active TCP connections and listeners.
type ConnectionTable struct {
	conns         map[ConnKey]*TCPConn
	listeners     map[uint16]*Listener
	mu            sync.RWMutex
	log           *zap.Logger
	ephemeralPort atomic.Uint32
}

var (
	ErrConnExists     = errors.New("connection already exists")
	ErrListenerExists = errors.New("listener already exists on port")
)

// NewConnectionTable creates a new connection table.
func NewConnectionTable(log *zap.Logger) *ConnectionTable {
	ct := &ConnectionTable{
		conns:     make(map[ConnKey]*TCPConn),
		listeners: make(map[uint16]*Listener),
		log:       log,
	}
	// Initialize ephemeral port start (IANA range 49152-65535)
	ct.ephemeralPort.Store(49152)
	return ct
}

// Register adds a new connection to the table.
func (ct *ConnectionTable) Register(conn *TCPConn) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if _, exists := ct.conns[conn.key]; exists {
		return ErrConnExists
	}
	ct.conns[conn.key] = conn
	return nil
}

// Remove deletes a connection from the table by its key.
func (ct *ConnectionTable) Remove(key ConnKey) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.conns, key)
}

// Lookup finds a connection by its key.
func (ct *ConnectionTable) Lookup(key ConnKey) (*TCPConn, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	conn, exists := ct.conns[key]
	return conn, exists
}

// LookupOrListener finds a connection based on packet 4-tuple. 
// If not found, looks for a listener on the destination port.
// Assumes the 4-tuple is constructed as seen by the local host (Src=Local, Dst=Remote)
// OR the caller matches the tuple orientation properly.
func (ct *ConnectionTable) LookupOrListener(srcIP, dstIP net.IP, srcPort, dstPort uint16) (*TCPConn, *Listener, error) {
	var src, dst [4]byte
	
	if srcIP4 := srcIP.To4(); srcIP4 != nil {
		copy(src[:], srcIP4)
	}
	if dstIP4 := dstIP.To4(); dstIP4 != nil {
		copy(dst[:], dstIP4)
	}

	key := ConnKey{
		SrcIP:   src,
		SrcPort: srcPort,
		DstIP:   dst,
		DstPort: dstPort,
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if conn, exists := ct.conns[key]; exists {
		return conn, nil, nil
	}

	if listener, exists := ct.listeners[dstPort]; exists {
		return nil, listener, nil
	}

	return nil, nil, errors.New("no connection or listener found")
}

// RegisterListener adds a listener to the given port.
func (ct *ConnectionTable) RegisterListener(port uint16, l *Listener) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if _, exists := ct.listeners[port]; exists {
		return ErrListenerExists
	}
	ct.listeners[port] = l
	return nil
}

// RemoveListener removes the listener on the given port.
func (ct *ConnectionTable) RemoveListener(port uint16) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.listeners, port)
}

// EphemeralPort returns a free ephemeral port (49152-65535).
func (ct *ConnectionTable) EphemeralPort() uint16 {
	for {
		port := ct.ephemeralPort.Add(1) - 1
		
		if port > 65535 {
			// Wrap around back to 49152 using CompareAndSwap to avoid race conditions resetting it wrong
			ct.ephemeralPort.CompareAndSwap(port+1, 49152+1)
			continue
		}
		
		p16 := uint16(port)
		
		// Ensure the port is not in use
		ct.mu.RLock()
		_, listenerExists := ct.listeners[p16]
		connExists := false
		for k := range ct.conns {
			// Check if any connection uses this as local source port
			if k.SrcPort == p16 {
				connExists = true
				break
			}
		}
		ct.mu.RUnlock()

		if !listenerExists && !connExists {
			return p16
		}
	}
}
