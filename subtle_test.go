// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.
package mqv

import (
	"fmt"
	"math/big"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/suite"
)

type TestSubtleIntSuite struct {
	testValues1 []uint      // list of interesting values of size 1
	testValues2 []SubtleInt // list of interesting values of size 2 (cross product)
	suite.Suite
}

func (t *TestSubtleIntSuite) SetupSuite() {
	const maxUint = ^uint(0)
	t.testValues1 = []uint{0, 1, 2, maxUint, maxUint - 1, maxUint - 2, maxUint >> 1, maxUint>>1 + 1, maxUint>>1 - 1}
	t.testValues2 = make([]SubtleInt, 0, len(t.testValues1)*len(t.testValues1))
	for _, a := range t.testValues1 {
		for _, b := range t.testValues1 {
			t.testValues2 = append(t.testValues2, SubtleInt{a, b})
		}
	}
}

func (t *TestSubtleIntSuite) TestEncoding() {
	bigX, ok := new(big.Int).SetString("11223344556677889900aabbccddeeff", 16)
	t.True(ok, "failed to parse int")

	constX := SubtleInt{0x9900AABBCCDDEEFF, 0x1122334455667788}
	t.Equal(bigX.Bytes(), constX.Bytes(), "bytes not equal")
	t.Equal(fmtHex(bigX), fmtHex(constX.Big()), "big not equal")
}

func (t *TestSubtleIntSuite) TestString() {
	x := SubtleInt{0x9900AABBCCDDEEFF, 0x1122334455667788}
	want := new(big.Int)
	want.SetString("11223344556677889900aabbccddeeff", 16)
	t.Equal(want.String(), x.String(), "string representation not equal")
}

func (t *TestSubtleIntSuite) TestConvertBytes() {
	constX := SubtleInt{0x9900AABBCCDDEEFF, 0x1122334455667788}
	bytesX := constX.Bytes()

	constY := make(SubtleInt, SubtleIntSize(8*len(bytesX)))
	constY.SetBytes(bytesX)

	t.Equal(constX, constY, "not equal")
}

func (t *TestSubtleIntSuite) TestBytesTrunc() {
	data := []byte{1, 2, 3}
	x := make(SubtleInt, SubtleIntSize(8*len(data)))
	x.SetBytes(data)

	got := x.Bytes()
	got = got[:len(data)]
	t.Equal(data, got)
}

func (t *TestSubtleIntSuite) TestAdd() {
	for _, a := range t.testValues2 {
		for _, b := range t.testValues2 {
			r := make(SubtleInt, 2)
			carry := r.Add(a, b)

			want := new(big.Int).Add(a.Big(), b.Big())
			t.Equalf(boolToW(want.BitLen() > 2*bits.UintSize), carry, "add(%v, %v).carry", a, b)
			want.SetBit(want, 2*bits.UintSize, 0)
			t.Equalf(fmtHex(want), fmtHex(r.Big()), "add(%v, %v)", a, b)

			t.Panics(func() { r.Add(a[:1], b) }, "must not add integers with different lengths")
			t.Panics(func() { r.Add(a, b[:1]) }, "must not add integers with different lengths")
		}
	}
}

func (t *TestSubtleIntSuite) TestSub() {
	for _, a := range t.testValues2 {
		for _, b := range t.testValues2 {
			r := make(SubtleInt, 2)
			borrow := r.Sub(a, b)

			want := new(big.Int).Sub(a.Big(), b.Big())
			t.Equalf(boolToW(want.Sign() < 0), borrow, "sub(%v, %v).borrow", a, b)
			if want.Sign() < 0 {
				want = twosComplement(want, 2*bits.UintSize)
				want.Abs(want)
				want.SetBit(want, 2*bits.UintSize, 0)
			}
			t.Equalf(fmtHex(want), fmtHex(r.Big()), "sub(%v, %v)", a, b)

			t.Panics(func() { r.Sub(a[:1], b) }, "must not subtract integers with different lengths")
			t.Panics(func() { r.Sub(a, b[:1]) }, "must not subtract integers with different lengths")
		}
	}
}

func (t *TestSubtleIntSuite) TestAddMod() {
	bigOne := big.NewInt(1)

	for _, a := range t.testValues2 {
		bigA := a.Big()
		for _, b := range t.testValues2 {
			bigB := b.Big()
			for _, n := range t.testValues2 {
				bigN := n.Big()

				if bigN.Cmp(bigOne) <= 0 || bigA.Cmp(bigN) >= 0 || bigB.Cmp(bigN) >= 0 {
					continue
				}

				r := make(SubtleInt, 2)
				r.AddMod(a, b, n)
				bigR := r.Big()

				bigWant := new(big.Int).Add(bigA, bigB)
				bigWant.Mod(bigWant, bigN)
				t.Equalf(fmtHex(bigWant), fmtHex(bigR), "addMod(%v, %v, %v)", a, b, n)

				t.Panics(func() { r.AddMod(a[:1], b, n) }, "must not addMod integers with different lengths")
				t.Panics(func() { r.AddMod(a, b[:1], n) }, "must not addMod integers with different lengths")
				t.Panics(func() { r.AddMod(a, b, n[:1]) }, "must not addMod integers with different lengths")
			}
		}
	}
}
func (t *TestSubtleIntSuite) TestLess() {
	for _, a := range t.testValues2 {
		for _, b := range t.testValues2 {
			less := a.Less(b)
			want := a.Big().Cmp(b.Big()) < 0
			t.Equal(boolToW(want), less, "less(%v, %v)", a, b)

			t.Panics(func() { a[:1].Less(b) }, "must not compare integers with different lengths")
			t.Panics(func() { a.Less(b[:1]) }, "must not compare integers with different lengths")
		}
	}
}

func (t *TestSubtleIntSuite) TestSelect() {
	for _, a := range t.testValues2 {
		for _, b := range t.testValues2 {
			r1 := make(SubtleInt, 2)
			r1.Select(1, a, b)

			r2 := make(SubtleInt, 2)
			r2.Select(0, a, b)

			t.Equal(a, r1, "select a")
			t.Equal(b, r2, "select b")

			t.Panics(func() { r1.Select(0, a[:1], b) }, "must not select integers with different lengths")
			t.Panics(func() { r1.Select(0, a[:1], b) }, "must not select integers with different lengths")
			t.Panics(func() { r1.Select(1, a, b[:1]) }, "must not select integers with different lengths")
			t.Panics(func() { r1.Select(1, a, b[:1]) }, "must not select integers with different lengths")
		}
	}
}

func (t *TestSubtleIntSuite) TestSelectW() {
	for _, a := range t.testValues1 {
		for _, b := range t.testValues1 {
			t.Equalf(a, selectW(1, a, b), "selectW(1, %v, %v)", a, b)
			t.Equalf(b, selectW(0, a, b), "selectW(0, %v, %v)", a, b)
		}
	}
}

func (t *TestSubtleIntSuite) TestLessEqW() {
	for _, a := range t.testValues1 {
		for _, b := range t.testValues1 {
			t.Equalf(boolToW(a <= b), lessEqW(a, b), "lessEqW(%v, %v)", a, b)
		}
	}
}

func (t *TestSubtleIntSuite) TestAddW() {
	bigOne := big.NewInt(1)

	for _, a := range t.testValues1 {
		bigA := new(big.Int).SetUint64(uint64(a))
		for _, b := range t.testValues1 {
			bigB := new(big.Int).SetUint64(uint64(b))

			sum0, carry0 := addW(a, b, 0)
			bigSum0 := new(big.Int).Add(bigA, bigB)
			t.Equalf(uint(bigSum0.Uint64()), sum0, "addW(%v, %v, 0).sum", a, b)
			t.Equalf(boolToW(bigSum0.BitLen() > bits.UintSize), carry0, "addW(%v, %v, 0).carry", a, b)

			sum1, carry1 := addW(a, b, 1)
			bigSum1 := new(big.Int).Add(bigSum0, bigOne)
			t.Equalf(uint(bigSum1.Uint64()), sum1, "addW(%v, %v, 1).sum", a, b)
			t.Equalf(boolToW(bigSum1.BitLen() > bits.UintSize), carry1, "addW(%v, %v, 1).carry", a, b)
		}
	}
}

func (t *TestSubtleIntSuite) TestSubW() {
	bigOne := big.NewInt(1)

	for _, a := range t.testValues1 {
		bigA := new(big.Int).SetUint64(uint64(a))
		for _, b := range t.testValues1 {
			bigB := new(big.Int).SetUint64(uint64(b))

			sub0, borrow0 := subW(a, b, 0)
			bigSub0 := new(big.Int).Sub(bigA, bigB)
			t.Equalf(uint(a-b), sub0, "subW(%v, %v, 0).sub", a, b)
			t.Equalf(boolToW(bigSub0.Sign() < 0), borrow0, "subW(%v, %v, 0).borrow", a, b)

			sub1, borrow2 := subW(a, b, 1)
			bigSub1 := new(big.Int).Sub(bigSub0, bigOne)
			t.Equalf(uint(a-b-1), sub1, "subW(%v, %v, 1).sub", a, b)
			t.Equalf(boolToW(bigSub1.Sign() < 0), borrow2, "subW(%v, %v, 1).borrow", a, b)
		}
	}
}

func TestSubtleInt(t *testing.T) {
	suite.Run(t, new(TestSubtleIntSuite))
}

func twosComplement(v *big.Int, numBits int) *big.Int {
	mask := new(big.Int)
	for i := 0; i < numBits; i++ {
		mask.SetBit(mask, i, 1)
	}
	x1 := new(big.Int).AndNot(v, mask)
	x2 := new(big.Int).And(v, mask)
	return x1.Sub(x1, x2)
}

func boolToW(v bool) uint {
	if v {
		return 1
	}
	return 0
}

func fmtHex(v *big.Int) string {
	return fmt.Sprintf("%v", v)
}
