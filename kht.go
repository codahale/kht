// Package kht provides an implementation of a keyed hash tree.
//
// A keyed hash tree is a hash tree which uses a keyed hash algorithm (e.g.,
// HMAC), used to derive block-level keys for encrypting large files.
//
// The notion of a keyed hash tree comes from Rajendran, Li, et al's papers on
// Horus, a large-scale encrypted storage system:
//
// http://www.ssrc.ucsc.edu/pub/rajendran11-pdsw.html
//
// https://www.usenix.org/conference/fast13/technical-sessions/presentation/li_yan
//
// This implementation derives keys from the level and the level offset, both
// encoded as little-endian 64-bit unsigned integers.
package kht

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"math"
)

// A KeyedHash is a hash algorithm which depends on a secret key.
type KeyedHash func(key []byte) hash.Hash

// HMAC returns a keyed hash implementation using the HMAC of the given hash
// algorithm.
func HMAC(alg func() hash.Hash) KeyedHash {
	return func(key []byte) hash.Hash {
		return hmac.New(alg, key)
	}
}

// A KeyedHashTree is a tree of keyed hashes, used to derive keys.
type KeyedHashTree struct {
	root                      []byte
	alg                       KeyedHash
	blockSize, maxSize, depth uint64
	factor                    float64
}

// New returns a KeyedHashTree with the given root key, keyed hash algorithm,
// block size, maximum size, and branching factor.
func New(key []byte, alg KeyedHash, blockSize, maxSize uint64, factor float64) *KeyedHashTree {
	return &KeyedHashTree{
		root:      key,
		alg:       alg,
		blockSize: blockSize,
		maxSize:   maxSize,
		factor:    factor,

		depth: uint64(
			math.Ceil(
				math.Log(float64(maxSize)/float64(blockSize)) /
					math.Log(factor),
			),
		),
	}
}

// Key returns the derived key at the given offset.
func (t *KeyedHashTree) Key(offset uint64) []byte {
	if offset > t.maxSize {
		panic("offset greater than maximum size")
	}

	buf := make([]byte, 16)
	k := make([]byte, len(t.root))
	copy(k, t.root)
	for i := uint64(0); i < t.depth; i++ {
		level := t.depth - i
		blockSize := uint64(math.Pow(t.factor, float64(level-1))) * t.blockSize
		y := offset / blockSize

		binary.LittleEndian.PutUint64(buf, uint64(i))
		binary.LittleEndian.PutUint64(buf[8:], uint64(y))

		h := t.alg(k)
		_, _ = h.Write(buf)
		k = h.Sum(k[:0])
	}
	return k
}
