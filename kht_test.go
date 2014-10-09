package kht_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"testing"

	"github.com/codahale/kht"
)

func TestKey(t *testing.T) {
	keys := [][]byte{
		{0x3a, 0xbe, 0x2f, 0xa3, 0xa0, 0xac, 0x9b, 0xa2, 0xa7, 0x4d, 0x17, 0xd4, 0x10, 0xb1, 0x30, 0x6},
		{0x3a, 0xbe, 0x2f, 0xa3, 0xa0, 0xac, 0x9b, 0xa2, 0xa7, 0x4d, 0x17, 0xd4, 0x10, 0xb1, 0x30, 0x6},
		{0x0, 0xe, 0x19, 0x5a, 0x57, 0x67, 0xc8, 0x69, 0xdb, 0xb7, 0x60, 0xc7, 0xae, 0xf7, 0x45, 0xe5},
		{0x0, 0xe, 0x19, 0x5a, 0x57, 0x67, 0xc8, 0x69, 0xdb, 0xb7, 0x60, 0xc7, 0xae, 0xf7, 0x45, 0xe5},
		{0x47, 0xd6, 0x23, 0x46, 0x88, 0x52, 0x11, 0xe5, 0xb1, 0xba, 0x78, 0x3c, 0x9d, 0x49, 0x81, 0x9d},
		{0x47, 0xd6, 0x23, 0x46, 0x88, 0x52, 0x11, 0xe5, 0xb1, 0xba, 0x78, 0x3c, 0x9d, 0x49, 0x81, 0x9d},
		{0x36, 0x65, 0xbc, 0xec, 0x2f, 0x34, 0xb, 0x96, 0x6f, 0xb2, 0x70, 0xeb, 0x4b, 0xed, 0x22, 0x55},
		{0x36, 0x65, 0xbc, 0xec, 0x2f, 0x34, 0xb, 0x96, 0x6f, 0xb2, 0x70, 0xeb, 0x4b, 0xed, 0x22, 0x55},
		{0x81, 0x15, 0xf5, 0x6e, 0x4, 0xd4, 0xe8, 0x4a, 0x9b, 0x8e, 0x45, 0xb8, 0x2f, 0xad, 0xd1, 0x55},
		{0x81, 0x15, 0xf5, 0x6e, 0x4, 0xd4, 0xe8, 0x4a, 0x9b, 0x8e, 0x45, 0xb8, 0x2f, 0xad, 0xd1, 0x55},
		{0xa6, 0x7, 0x3d, 0x82, 0x8e, 0x64, 0x27, 0x5e, 0x2a, 0x1e, 0x91, 0xcd, 0xef, 0x2f, 0xe9, 0x81},
		{0xa6, 0x7, 0x3d, 0x82, 0x8e, 0x64, 0x27, 0x5e, 0x2a, 0x1e, 0x91, 0xcd, 0xef, 0x2f, 0xe9, 0x81},
		{0x4d, 0xbd, 0x5a, 0x62, 0x2d, 0x23, 0xd5, 0x27, 0x92, 0x8e, 0x69, 0x1d, 0x3d, 0xfe, 0xb1, 0x20},
		{0x4d, 0xbd, 0x5a, 0x62, 0x2d, 0x23, 0xd5, 0x27, 0x92, 0x8e, 0x69, 0x1d, 0x3d, 0xfe, 0xb1, 0x20},
		{0xe0, 0x9, 0x48, 0xcc, 0x3a, 0x86, 0xcc, 0x31, 0x90, 0x73, 0xe1, 0x3f, 0x63, 0x75, 0x3d, 0xdf},
		{0xe0, 0x9, 0x48, 0xcc, 0x3a, 0x86, 0xcc, 0x31, 0x90, 0x73, 0xe1, 0x3f, 0x63, 0x75, 0x3d, 0xdf},
	}

	n := uint64(16)
	tree := kht.New([]byte("yay"), kht.HMAC(md5.New), 2, n, 8)
	for i := uint64(0); i < n; i++ {
		if v, want := tree.Key(i), keys[i]; !bytes.Equal(v, want) {
			t.Errorf("Key %d was %#v, but expected %#v", i, v, want)
		}
	}
}

func TestOffsetTooGreat(t *testing.T) {
	defer func() {
		e := recover()
		if e != "offset greater than maximum size" {
			t.Errorf("Panic was %v, which is weird", e)
		}
	}()

	tree := kht.New([]byte("yay"), kht.HMAC(md5.New), 2, 100, 8)
	tree.Key(1000)
	t.Error("No panic, but expected one")
}

func BenchmarkKey(b *testing.B) {
	tree := kht.New(make([]byte, 32), kht.HMAC(sha256.New), 1024, 1<<32, 8)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tree.Key(0)
	}
}
