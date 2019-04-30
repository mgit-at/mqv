// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

package mqv

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/suite"
)

type MQVTestSuite struct {
	Curve elliptic.Curve
	suite.Suite

	aliceStaticPriv    []byte
	aliceStaticX       *big.Int
	aliceStaticY       *big.Int
	aliceEphemeralPriv []byte
	aliceEphemeralX    *big.Int
	aliceEphemeralY    *big.Int
	bobStaticPriv      []byte
	bobStaticX         *big.Int
	bobStaticY         *big.Int
	bobEphemeralPriv   []byte
	bobEphemeralX      *big.Int
	bobEphemeralY      *big.Int
}

func (s *MQVTestSuite) SetupTest() {
	s.aliceStaticPriv, s.aliceStaticX, s.aliceStaticY = s.generateKey("alice static")
	s.aliceEphemeralPriv, s.aliceEphemeralX, s.aliceEphemeralY = s.generateKey("alice ephemeral")
	s.bobStaticPriv, s.bobStaticX, s.bobStaticY = s.generateKey("bob static")
	s.bobEphemeralPriv, s.bobEphemeralX, s.bobEphemeralY = s.generateKey("bob ephemeral")
}

func (s *MQVTestSuite) generateKey(name string) ([]byte, *big.Int, *big.Int) {
	priv, x, y, err := elliptic.GenerateKey(s.Curve, rand.Reader)
	s.NoErrorf(err, "failed to create key %q", name)
	return priv, x, y
}

func (s *MQVTestSuite) TestSimple() {
	aliceX, aliceY, err := MQV(s.aliceStaticPriv, s.aliceEphemeralPriv,
		s.aliceEphemeralX, s.bobStaticX, s.bobStaticY, s.bobEphemeralX, s.bobEphemeralY, s.Curve)
	s.NoError(err, "failed to run mqv for alice")

	bobX, bobY, err := MQV(s.bobStaticPriv, s.bobEphemeralPriv,
		s.bobEphemeralX, s.aliceStaticX, s.aliceStaticY, s.aliceEphemeralX, s.aliceEphemeralY, s.Curve)
	s.NoError(err, "failed to run mqv for bob")

	s.EqualBig(aliceX, bobX, "x is not equal")
	s.EqualBig(aliceY, bobY, "y is not equal")
}

func (s *MQVTestSuite) TestBlinded() {
	aliceX, aliceY, err := MQV(s.aliceStaticPriv, s.aliceEphemeralPriv,
		s.aliceEphemeralX, s.bobStaticX, s.bobStaticY, s.bobEphemeralX, s.bobEphemeralY, s.Curve)
	s.NoError(err, "failed to run simple mqv for alice")

	aliceBlindX, aliceBlindY, err := BlindMQV(s.aliceStaticPriv, s.aliceEphemeralPriv,
		s.aliceEphemeralX, s.bobStaticX, s.bobStaticY, s.bobEphemeralX, s.bobEphemeralY, s.Curve, rand.Reader)
	s.NoError(err, "failed to run blinded mqv for alice")

	s.EqualBig(aliceX, aliceBlindX, "x is not equal")
	s.EqualBig(aliceY, aliceBlindY, "y is not equal")
}

func (s *MQVTestSuite) EqualBig(expected, actual *big.Int, msg string) {
	s.T().Helper()
	s.Equal(expected.Text(16), actual.Text(16), msg)
}
func TestMQVP224(t *testing.T) {
	suite.Run(t, &MQVTestSuite{Curve: elliptic.P224()})
}

func TestMQVP256(t *testing.T) {
	suite.Run(t, &MQVTestSuite{Curve: elliptic.P256()})
}

func TestMQVP384(t *testing.T) {
	suite.Run(t, &MQVTestSuite{Curve: elliptic.P384()})
}

func TestMQVP521(t *testing.T) {
	suite.Run(t, &MQVTestSuite{Curve: elliptic.P521()})
}
