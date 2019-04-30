// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package mqv

import (
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/pkg/errors"
)

var genMask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// GenerateKey returns a public / private key pair. The private key is
// generated using the given reader, which must return random data.
func GenerateKey(params *elliptic.CurveParams, rand io.Reader) ([]byte, error) {
	numBits := params.N.BitLen()
	numBytes := (numBits + 7) >> 3
	constN := make(SubtleInt, SubtleIntSize(numBits))
	constN.SetBytes(params.N.Bytes())

	priv := make([]byte, numBytes)
	tmp := make(SubtleInt, len(constN))
	defer tmp.SetZero()

	for {
		_, err := io.ReadFull(rand, priv)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate random data")
		}

		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		priv[0] &= genMask[numBits%8]
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		tmp.SetBytes(priv)
		if tmp.Less(constN) == 1 {
			return priv, nil
		}
	}
}

// BlindKey blinds the original private key (p) with a random blind key (b)
// and returns (p+b, -b) mod n.
func BlindKey(priv []byte, params *elliptic.CurveParams, rand io.Reader) ([]byte, []byte, error) {
	numBytes := ((params.N.BitLen() + 7) >> 3)
	n := make(SubtleInt, SubtleIntSize(8*numBytes))
	n.SetBytes(params.N.Bytes())

	if len(priv) > numBytes {
		return nil, nil, errors.New("invalid private key")
	}

	privConst := make(SubtleInt, len(n))
	privConst.SetBytes(priv)

	blindBytes, err := GenerateKey(params, rand)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate blind key")
	}
	defer WipeBytes(blindBytes)

	blind := make(SubtleInt, len(n))
	defer blind.SetZero()
	blind.SetBytes(blindBytes)

	privNew := make(SubtleInt, len(n))
	defer privNew.SetZero()
	privNew.SetBytes(priv)
	privNew.AddMod(privNew, blind, n)

	blind.Sub(n, blind)

	return privNew.Bytes()[:numBytes], blind.Bytes()[:numBytes], nil
}

// ScalarMultBlind is similar to to the elliptic.ScalarMult function, but it
// does two scalar multiplications with the blinded keys instead and adds the
// afterwards.
func ScalarMultBlind(x *big.Int, y *big.Int, priv []byte, curve elliptic.Curve, rand io.Reader) (*big.Int, *big.Int, error) {
	privBlind, privBlindInv, err := BlindKey(priv, curve.Params(), rand)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to blind key")
	}
	x1, y1 := curve.ScalarMult(x, y, privBlind)
	x2, y2 := curve.ScalarMult(x, y, privBlindInv)
	x3, y3 := curve.Add(x1, y1, x2, y2)
	return x3, y3, nil
}

// WipeInt overrides the internal array of a big.Int with zeros.
func WipeInt(x *big.Int) {
	words := x.Bits()
	for i := range words {
		words[i] = 0
	}
}

// WipeBytes overrides the internal byte array with zeros.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
