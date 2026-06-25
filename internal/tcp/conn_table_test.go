package tcp

import (
	"net"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestConnectionTable_RegisterRemoveLookup(t *testing.T) {
	log := zaptest.NewLogger(t)
	ct := NewConnectionTable(log)

	key := ConnKey{
		SrcIP:   [4]byte{10, 0, 0, 1},
		SrcPort: 12345,
		DstIP:   [4]byte{10, 0, 0, 2},
		DstPort: 80,
	}

	conn := &TCPConn{key: key}

	// Lookup non-existent
	if _, ok := ct.Lookup(key); ok {
		t.Errorf("expected connection to not exist")
	}

	// Register
	if err := ct.Register(conn); err != nil {
		t.Fatalf("expected successful registration, got %v", err)
	}

	// Register duplicate
	if err := ct.Register(conn); err != ErrConnExists {
		t.Fatalf("expected ErrConnExists, got %v", err)
	}

	// Lookup existing
	if found, ok := ct.Lookup(key); !ok || found != conn {
		t.Errorf("expected to find connection")
	}

	// Remove
	ct.Remove(key)
	if _, ok := ct.Lookup(key); ok {
		t.Errorf("expected connection to be removed")
	}
}

func TestConnectionTable_Listeners(t *testing.T) {
	log := zaptest.NewLogger(t)
	ct := NewConnectionTable(log)

	listener := &Listener{Port: 8080}

	// Register
	if err := ct.RegisterListener(8080, listener); err != nil {
		t.Fatalf("expected successful registration, got %v", err)
	}

	// Register duplicate
	if err := ct.RegisterListener(8080, listener); err != ErrListenerExists {
		t.Fatalf("expected ErrListenerExists, got %v", err)
	}

	// Remove
	ct.RemoveListener(8080)

	// Register after remove should succeed
	if err := ct.RegisterListener(8080, listener); err != nil {
		t.Fatalf("expected successful registration after removal, got %v", err)
	}
}

func TestConnectionTable_LookupOrListener(t *testing.T) {
	log := zaptest.NewLogger(t)
	ct := NewConnectionTable(log)

	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("10.0.0.1").To4()
	var srcArr, dstArr [4]byte
	copy(srcArr[:], srcIP)
	copy(dstArr[:], dstIP)

	key := ConnKey{
		SrcIP:   srcArr,
		SrcPort: 50000,
		DstIP:   dstArr,
		DstPort: 80,
	}
	conn := &TCPConn{key: key}
	listener := &Listener{Port: 8080}

	ct.Register(conn)
	ct.RegisterListener(8080, listener)

	// Case 1: Match connection exactly
	foundConn, foundListener, err := ct.LookupOrListener(srcIP, dstIP, 50000, 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if foundConn != conn || foundListener != nil {
		t.Errorf("expected to find connection, got conn=%v listener=%v", foundConn, foundListener)
	}

	// Case 2: Match listener
	foundConn, foundListener, err = ct.LookupOrListener(srcIP, dstIP, 50000, 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if foundListener != listener || foundConn != nil {
		t.Errorf("expected to find listener, got conn=%v listener=%v", foundConn, foundListener)
	}

	// Case 3: No match
	foundConn, foundListener, err = ct.LookupOrListener(srcIP, dstIP, 50000, 9090)
	if err == nil {
		t.Fatalf("expected error for no match")
	}
}

func TestConnectionTable_EphemeralPort(t *testing.T) {
	log := zaptest.NewLogger(t)
	ct := NewConnectionTable(log)

	port1 := ct.EphemeralPort()
	if port1 < 49152 || port1 > 65535 {
		t.Errorf("ephemeral port out of range: %d", port1)
	}

	port2 := ct.EphemeralPort()
	if port2 == port1 {
		t.Errorf("ephemeral port should increment")
	}

	// Simulate collision
	ct.RegisterListener(port2+1, &Listener{Port: port2 + 1})
	port3 := ct.EphemeralPort() // should skip port2+1 and go to port2+2
	if port3 != port2+2 {
		t.Errorf("expected ephemeral port to skip registered listener, got %d", port3)
	}
}
