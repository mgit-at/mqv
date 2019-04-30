// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package mqv

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"

	"github.com/pkg/errors"
)

var (
	one = big.NewInt(1)
)

// cofactor returns the cofactor (number of points on the elliptic curve vs.
// number of elements in the cyclic group) of the elliptic curve.
func cofactor(curve elliptic.Curve) (*big.Int, error) {
	switch curve {
	case elliptic.P224():
		return one, nil
	case elliptic.P256():
		return one, nil
	case elliptic.P384():
		return one, nil
	case elliptic.P521():
		return one, nil
	default:
		return nil, fmt.Errorf("failed to determine cofactor of curve %q", curve.Params().Name)
	}
}

// avf is the associative value function. It is used by the ECC MQV family of
// key-agreement schemes to compute an integer that is associated with an
// elliptic curve point. This function implements the recommendation given
// by section 5.7.2.2 in SP 800-56A Rev. 3.
func avf(x *big.Int, params *elliptic.CurveParams) *big.Int {
	f := uint(params.N.BitLen())        // f = ceil(log2(n))
	b := new(big.Int).Lsh(one, (f+1)/2) // b = 2^ceil(f/2)
	defer WipeInt(b)

	// v = (x mod b) + b = ((b - 1) & x) + b
	v := new(big.Int)
	v = v.Sub(b, one)
	v = v.And(v, x)
	v = v.Add(v, b)
	return v
}

// mqvSig calculates h * (ownEphemeralPriv + avf(ownEphemeralPublic) * ownStaticPriv)) mod n
func mqvSig(ownStaticPriv, ownEphemeralPriv []byte, ownEphemeralX *big.Int, curve elliptic.Curve, h *big.Int) []byte {
	params := curve.Params()
	ownStaticPrivInt := new(big.Int).SetBytes(ownStaticPriv)
	defer WipeInt(ownStaticPrivInt)
	ownEphemeralPrivInt := new(big.Int).SetBytes(ownEphemeralPriv)
	defer WipeInt(ownEphemeralPrivInt)
	implSig := avf(ownEphemeralX, params)
	defer WipeInt(implSig)
	implSig = implSig.Mul(implSig, ownStaticPrivInt)
	implSig = implSig.Add(implSig, ownEphemeralPrivInt)
	implSig = implSig.Mod(implSig, params.N)
	implSig = implSig.Mul(implSig, h)
	return implSig.Bytes()
}

// mqvBase calculates otherEphemeralPublic + avf(otherEphemeralPublic) * otherStaticPublic.
func mqvBase(otherStaticX, otherStaticY, otherEphemeralX, otherEphemeralY *big.Int, curve elliptic.Curve) (*big.Int, *big.Int) {
	avfOther := avf(otherEphemeralX, curve.Params())
	defer WipeInt(avfOther)
	avfOtherBytes := avfOther.Bytes()
	defer WipeBytes(avfOtherBytes)

	ax, ay := curve.ScalarMult(otherStaticX, otherStaticY, avfOtherBytes)
	defer WipeInt(ax)
	defer WipeInt(ay)

	bx, by := curve.Add(otherEphemeralX, otherEphemeralY, ax, ay)
	return bx, by
}

// MQV implements the ECC MQV primitive that calculates a shared secret
// based on the domain parameters, the own public and private keys and the
// other party's public keys. In the full form, each party has a static
// and a ephemeral key. In the one-pass form the other party only has
// a static key which is used twice with this primitive.
// h is the cofactor of the elliptic curve.
// See section 5.7.2.3 of SP 800-56A Rev. 3 for more details.
func MQV(ownStaticPriv, ownEphemeralPriv []byte, ownEphemeralX, otherStaticX, otherStaticY, otherEphemeralX, otherEphemeralY *big.Int, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	h, err := cofactor(curve)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get cofactor")
	}

	s := mqvSig(ownStaticPriv, ownEphemeralPriv, ownEphemeralX, curve, h)
	defer WipeBytes(s)

	bx, by := mqvBase(otherStaticX, otherStaticY, otherEphemeralX, otherEphemeralY, curve)
	defer WipeInt(bx)
	defer WipeInt(by)

	x, y := curve.ScalarMult(bx, by, s)
	if x.Sign() == 0 {
		return nil, nil, fmt.Errorf("failed to generate shared secret")
	}
	return x, y, nil
}

// BlindMQV implements the ECC MQV primitive with additional blinding
// to prevent side channel attacks.
//
// Usually Z is calculated with mqvSig(ownStaticPriv, ownEphemeralPriv) * mqvBase()
// (see mqvSimple), but this might leak information about the private keys on
// various side channels (e.g. timing or power consumption) since neither
// the elliptic curve implementation nor the big number implementation is
// constant time.
// Therefore we blind each key by a random number 0 <= r < n. Assuming r is
// completely random, then (originalPrivKey + r) mod n has also full entropy,
// as well as -r mod n. We do this for both private keys. The blinding process
// (simple addition / substraction modulo n) is done in constant time and
// the random numbers are kept secret.
// Z is now calculated by mqvSig(ownStaticPriv + r1, ownEphemeralPriv + r2) *
// mqvBase() + mqvSig(-r1, -r2) * mqvBase(), which are basically two MQV
// primitives with random keys instead of one using the original key.
func BlindMQV(ownStaticPriv, ownEphemeralPriv []byte, ownEphemeralX, otherStaticX, otherStaticY, otherEphemeralX, otherEphemeralY *big.Int, curve elliptic.Curve, rand io.Reader) (*big.Int, *big.Int, error) {
	params := curve.Params()
	h, err := cofactor(curve)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get cofactor")
	}

	ownStaticPrivNew, ownStaticPrivRev, err := BlindKey(ownStaticPriv, params, rand)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to blind static key")
	}
	defer WipeBytes(ownStaticPrivNew)
	defer WipeBytes(ownStaticPrivRev)

	ownEphemeralPrivNew, ownEphemeralPrivRev, err := BlindKey(ownEphemeralPriv, params, rand)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to blind ephemeral key")
	}
	defer WipeBytes(ownEphemeralPrivNew)
	defer WipeBytes(ownEphemeralPrivRev)

	bx, by := mqvBase(otherStaticX, otherStaticY, otherEphemeralX, otherEphemeralY, curve)
	defer WipeInt(bx)
	defer WipeInt(by)

	s1 := mqvSig(ownStaticPrivNew, ownEphemeralPrivNew, ownEphemeralX, curve, h)
	defer WipeBytes(s1)

	x1, y1 := curve.ScalarMult(bx, by, s1)
	defer WipeInt(x1)
	defer WipeInt(y1)

	s2 := mqvSig(ownStaticPrivRev, ownEphemeralPrivRev, ownEphemeralX, curve, h)
	defer WipeBytes(s2)

	x2, y2 := curve.ScalarMult(bx, by, s2)
	defer WipeInt(x2)
	defer WipeInt(y2)

	x, y := curve.Add(x1, y1, x2, y2)
	return x, y, nil
}
