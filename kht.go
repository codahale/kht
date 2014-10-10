// Package kht provides an implementation of a keyed hash tree.
//
// A keyed hash tree is a hash tree which uses a keyed hash algorithm (e.g.,
// HMAC), used to derive block-level keys for encrypting large files.
//
// The notion of a keyed hash tree comes from Rajendran, Li, et al's papers on
// Horus, a large-scale encrypted storage system
// (http://www.ssrc.ucsc.edu/pub/rajendran11-pdsw.html and
// https://www.usenix.org/conference/fast13/technical-sessions/presentation/li_yan).
//
// A keyed hash tree with a branching factor of 2 has log2(maxSize/blockSize)
// levels, each with increasing numbers of keys.
//
//     +-----------------------------------------------------------------------+
//     |                                K(0,0)                                 |
//     +-----------------------------------+-----------------------------------+
//     |              K(1,0)               |              K(1,1)               |
//     +-----------------+-----------------+-----------------+-----------------+
//     |      K(2,0)     |     K(2,1)            K(2,3)      |     K(2,4)      |
//     +--------+--------+--------+--------+--------+--------+--------+--------+
//     | K(3,0) | K(3,1) | K(3,2) | K(3,3) | K(3,4) | K(3,5) | K(3,6) | K(3,7) |
//     +--------+--------+--------+--------+--------+--------+--------+--------+
//
// The root node (the top of the diagram) uses the tree's root key, and the leaf
// nodes (the bottom of the diagram) contain the keys used to encrypt the
// corresponding blocks of data. The nodes are not materialized, which means a
// keyed hash table takes a very small amount of memory (~100 bytes), and
// deriving block keys is very fast (~8μs for each 1KiB block of a 2GiB tree
// with a branching factor of 1024 using SHA-256).
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
