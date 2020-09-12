// Copyright 2018 Nicko van Someren
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// SPDX-License-Identifier: Apache-2.0

/*
Package pssst implements the Packet Security for Stateless Server Transactions
(PSSST) protocol and provides simple interfaces for both client and server ends.
*/
package gopssst

import (
	"crypto"
	"crypto/rand"
	"io"
)

type header struct {
	Flags, CipherSuite uint16
}

const (
	flagsReply      = 1 << 15
	flagsClientAuth = 1 << 14
)

const (
	CipherSuiteX25519AESGCM = 1
)

/*
ReplyHandler is a function type for functions that either pack a reply message into and
encrypted packet (when used at the server) or unpack an encrypted reply to yield the
reply message (when used at the client).
*/
type ReplyHandler func(data []byte) (reply []byte, err error)

type Server interface {
	UnpackIncoming(packetBytes []byte) (data []byte, replyHandler ReplyHandler, clientPublicKey crypto.PublicKey, err error)
}

type Client interface {
	PackOutgoing(data []byte) (packetBytes []byte, replyHandler ReplyHandler, err error)
}

func NewServer(cipherSuite int, serverPrivateKey crypto.PrivateKey) (server Server, err error) {
	switch cipherSuite {
	case CipherSuiteX25519AESGCM:
		keyBytes, ok := serverPrivateKey.([]byte)
		if !ok {
			err = &PSSSTError{"Incompatible key"}
			return
		}

		serverStruct := serverX22519AESGCM128{keyBytes}
		server = &serverStruct
	default:
		err = &PSSSTError{"Unsuported cipher suite"}
	}

	return
}

func NewClient(cipherSuite int, serverPublicKey crypto.PublicKey, clientPrivateKey crypto.PrivateKey) (client Client, err error) {
	switch cipherSuite {
	case CipherSuiteX25519AESGCM:
		serverKeyBytes, ok := serverPublicKey.([]byte)
		if !ok {
			err = &PSSSTError{"Incompatible server key"}
			return
		}

		var clientKeyBytes []byte
		if clientPrivateKey != nil {
			clientKeyBytes, ok = clientPrivateKey.([]byte)
			if !ok {
				err = &PSSSTError{"Incompatible client key"}
				return
			}
		}

		clientStruct := clientX25519AESGCM128{serverKeyBytes, clientKeyBytes, nil, nil}
		client = &clientStruct
	default:
		err = &PSSSTError{"Unsuported cipher suite"}
	}

	return
}

func GenerateKeyPair(cipherSuite int, random io.Reader) (privateKey crypto.PrivateKey, publicKey crypto.PublicKey, err error) {
	if random == nil {
		random = rand.Reader
	}

	switch cipherSuite {
	case CipherSuiteX25519AESGCM:
		privateKey, publicKey, err = generateX22519Pair(random)
	default:
		err = &PSSSTError{"Unsuported cipher suite"}
	}

	return
}
