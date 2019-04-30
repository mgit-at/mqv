// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package mqv

import (
	"math/big"
	"math/bits"
)

// SubtleIntSize returns the size of a SubtleInt that can store at least
// numBits of information.
func SubtleIntSize(numBits int) int {
	const wordSize = bits.UintSize / 8
	numBytes := ((numBits + 7) >> 3)
	numWords := (numBytes + wordSize - 1) / wordSize
	return numWords
}

// SubtleInt represents a non-negative big integer with a fixed size. All
// operations on this integer are performed in constant time.
type SubtleInt []uint

// Add sets z to the sum x+y and returns the carry.
func (z SubtleInt) Add(x, y SubtleInt) uint {
	if len(x) != len(y) || len(x) != len(z) {
		panic("size mismatch")
	}
	var c uint
	for i := range x {
		z[i], c = addW(x[i], y[i], c)
	}
	return c
}

// Sub sets z to the difference x-y and returns the borrow.
func (z SubtleInt) Sub(x, y SubtleInt) uint {
	if len(x) != len(y) || len(x) != len(z) {
		panic("size mismatch")
	}
	var c uint
	for i := range x {
		z[i], c = subW(x[i], y[i], c)
	}
	return c
}

// AddMod sets z to x+y mod n. Both parameters x and y must be less than n.
func (z SubtleInt) AddMod(x, y, n SubtleInt) {
	tmp := make(SubtleInt, len(x))
	c1 := z.Add(x, y)
	c2 := tmp.Sub(z, n)
	if c1&^c2 == 1 {
		panic("can not happen")
	}
	z.Select(c1^c2, z, tmp)
}

// Select sets z to x if p = 1 and y if p = 0.
func (z SubtleInt) Select(p uint, x, y SubtleInt) {
	if len(x) != len(y) || len(x) != len(z) {
		panic("size mismatch")
	}
	for i := range x {
		z[i] = selectW(p, x[i], y[i])
	}
}

// Less returns 1 if z < y and 0 otherwise.
func (z SubtleInt) Less(y SubtleInt) uint {
	if len(z) != len(y) {
		panic("size mismatch")
	}
	undecided := uint(1)
	isLess := uint(0)
	for i := len(z) - 1; i >= 0; i-- {
		less1 := lessW(z[i], y[i])
		less2 := lessW(y[i], z[i])

		notequal := less1 | less2
		isLess = selectW(undecided&notequal, less1, isLess)
		undecided &= ^notequal
	}
	return isLess
}

// SetZero sets z to zero.
func (z SubtleInt) SetZero() {
	for i := range z {
		z[i] = 0
	}
}

// SetBytes interprets buf as a big-endian byte slice and sets z to this value.
func (z SubtleInt) SetBytes(buf []byte) {
	z.SetZero()
	i, s := len(z)-1, uint(bits.UintSize)
	for _, x := range buf {
		s -= 8
		z[i] |= uint(x) << s
		if s == 0 {
			s = bits.UintSize
			i--
		}
	}
}

// Bytes returns the value of z as a big-endian byte slice.
func (z SubtleInt) Bytes() []byte {
	const sizeBytes = bits.UintSize / 8
	r := make([]byte, len(z)*sizeBytes)
	i := len(r) - 1
	for _, x := range z {
		for s := uint(0); s < bits.UintSize; s += 8 {
			r[i] = uint8(x >> s)
			i--
		}
	}
	return r
}

// Big converts the integer z to a big.Int.
func (z SubtleInt) Big() *big.Int {
	return new(big.Int).SetBytes(z.Bytes())
}

// String returns the value of z.
func (z SubtleInt) String() string {
	return z.Big().String()
}

// selectW returns a if v is 1 and b if v is 0.
func selectW(v, a, b uint) uint {
	return ^(v-1)&a | (v-1)&b
}

// lessEqW returns 1 if a <= b  and 0 if a > b.
func lessEqW(a, b uint) uint {
	msbA := (a >> (bits.UintSize - 1)) & 1
	msbB := (b >> (bits.UintSize - 1)) & 1
	remA := a &^ (1 << (bits.UintSize - 1))
	remB := b &^ (1 << (bits.UintSize - 1))
	less := ((remA - remB - 1) >> (bits.UintSize - 1)) & 1
	return selectW((msbA^msbB)&1, msbB, less)
}

// lessW returns 1 if a < b and 0 if a >= b.
func lessW(a, b uint) uint {
	return lessEqW(b, a) ^ 1
}

// z1<<_W + z0 = a+b+c, with c == 0 or 1
func addW(a, b, c uint) (z0, z1 uint) {
	bc := b + c
	z0 = a + bc
	z1 = lessW(z0, a) | lessW(bc, b)
	return
}

// z1<<_W + z0 = a-b-c, with c == 0 or 1
func subW(a, b, c uint) (z0, z1 uint) {
	bc := b + c
	z0 = a - bc
	z1 = lessW(a, z0) | lessW(bc, b)
	return
}
