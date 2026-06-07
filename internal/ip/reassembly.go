package ip

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	ErrInvalidFragment = errors.New("invalid fragment")
)

type ReassemblyStats struct {
	GroupsActive   int
	FragmentsAdded int
	Reassembled    int
	Evicted        int
}

type ReassemblyBuffer struct {
	groups     map[fragmentKey]*fragmentGroup
	mu         sync.Mutex
	ticker     *time.Ticker
	onComplete func(reassembled []byte)
	log        *zap.Logger

	stats ReassemblyStats
}

type fragmentKey struct {
	src   [4]byte
	dst   [4]byte
	id    uint16
	proto uint8
}

type fragmentGroup struct {
	fragments map[uint16][]byte
	totalLen  int
	received  int
	createdAt time.Time
}

// NewReassemblyBuffer creates a new buffer for reassembling IP fragments.
func NewReassemblyBuffer(onComplete func([]byte), log *zap.Logger) *ReassemblyBuffer {
	if log == nil {
		log = zap.NewNop()
	}
	return &ReassemblyBuffer{
		groups:     make(map[fragmentKey]*fragmentGroup),
		onComplete: onComplete,
		log:        log,
	}
}

// Add adds a fragment to the buffer. If it completes a packet, it calls onComplete.
func (b *ReassemblyBuffer) Add(fragment []byte) error {
	header, err := ParseHeader(fragment)
	if err != nil {
		return err
	}

	isFrag := (header.Flags&FlagMF != 0) || header.FragOffset > 0
	if !isFrag {
		// Not a fragment, deliver immediately
		b.onComplete(fragment)
		return nil
	}

	key := fragmentKey{
		id:    header.ID,
		proto: header.Protocol,
	}
	copy(key.src[:], header.Src.To4())
	copy(key.dst[:], header.Dst.To4())

	b.mu.Lock()

	group, exists := b.groups[key]
	if !exists {
		group = &fragmentGroup{
			fragments: make(map[uint16][]byte),
			createdAt: time.Now(),
			totalLen:  -1, // unknown until we see the last fragment
		}
		b.groups[key] = group
		b.stats.GroupsActive++
	}

	offset := header.FragOffset * 8
	payload := header.Payload(fragment)
	payloadLen := len(payload)

	if _, duplicate := group.fragments[header.FragOffset]; !duplicate {
		group.fragments[header.FragOffset] = fragment
		group.received += payloadLen
		b.stats.FragmentsAdded++
	}

	isLast := (header.Flags & FlagMF) == 0
	if isLast {
		group.totalLen = int(offset) + payloadLen
	}

	var reassembled []byte
	if group.totalLen > 0 && group.received == group.totalLen {
		reassembled, err = b.reassemble(group)
		if err != nil {
			b.log.Error("failed to reassemble fragments", zap.Error(err))
		}
		delete(b.groups, key)
		b.stats.GroupsActive--
		if reassembled != nil {
			b.stats.Reassembled++
		}
	}

	b.mu.Unlock()

	if reassembled != nil {
		b.onComplete(reassembled)
	}

	return nil
}

func (b *ReassemblyBuffer) reassemble(group *fragmentGroup) ([]byte, error) {
	firstFrag, ok := group.fragments[0]
	if !ok {
		return nil, ErrInvalidFragment
	}

	header, err := ParseHeader(firstFrag)
	if err != nil {
		return nil, err
	}

	headerLen := header.HeaderLen()
	fullPacketLen := headerLen + group.totalLen

	fullPacket := make([]byte, fullPacketLen)

	newHeader := *header
	newHeader.Flags &^= FlagMF
	newHeader.FragOffset = 0
	newHeader.TotalLen = uint16(fullPacketLen)
	newHeader.Checksum = 0

	headerBytes, _ := newHeader.Marshal()
	newHeader.Checksum = Checksum(headerBytes)
	headerBytes, _ = newHeader.Marshal()

	copy(fullPacket, headerBytes)

	for offset, frag := range group.fragments {
		fragHeader, _ := ParseHeader(frag)
		payload := fragHeader.Payload(frag)
		byteOffset := headerLen + int(offset)*8
		copy(fullPacket[byteOffset:], payload)
	}

	return fullPacket, nil
}

// Start begins the background cleanup routine for stale fragments.
func (b *ReassemblyBuffer) Start(ctx context.Context) {
	b.ticker = time.NewTicker(10 * time.Second)
	go func() {
		defer b.ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-b.ticker.C:
				b.cleanup(now)
			}
		}
	}()
}

func (b *ReassemblyBuffer) cleanup(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, group := range b.groups {
		if now.Sub(group.createdAt) > 30*time.Second {
			delete(b.groups, key)
			b.stats.GroupsActive--
			b.stats.Evicted++
			b.log.Debug("evicted stale fragment group", zap.Uint16("id", key.id))
		}
	}
}

// Stats returns the current reassembly statistics.
func (b *ReassemblyBuffer) Stats() ReassemblyStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}
