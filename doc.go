// Copyright (c) 2017 mgIT GmbH. All rights reserved.
// Distributed under the Apache License. See LICENSE for details.

// Package mqv implements MQV ECC as described in
// "NIST Special Publication 800-56A Revision 3".
//
// MQV is a key agreement protocol similar to Diffie-Hellman, but instead of
// using 2 ephemeral keys C(2e, 0s), MQV uses 2 ephemeral and 2 static keys
// C(2e, 2s) in the full variant. The static keys are previously distributed
// and will be used to authenticate the parties.
//
// Another advantage of MQV is the "one-pass" mode C(1e, 2s) which allows
// senders and receivers to transmit data without a full roundtrip for the key
// agreement. In this case, the sender uses the static key of the other party
// twice (its safe to pass a key twice, once as static key and once as ephemeral
// key), and the receiver uses his own static key twice to decode the message.
//
// In addition to the basic MQV primitive, this package also implements a
// blinded version BlindMQV, which blinds the keys before doing the computations
// in order to prevent side channel attacks.
//
// Please see
// https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
// for more details.
package mqv
