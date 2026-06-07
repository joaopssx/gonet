package ip

import (
	"testing"
)

func BenchmarkChecksum1KB(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Checksum(data)
	}
}

func BenchmarkChecksum64KB(b *testing.B) {
	data := make([]byte, 65535)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Checksum(data)
	}
}
