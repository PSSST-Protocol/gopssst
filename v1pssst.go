package gopssst

import (
	"io"
	"bytes"
	"crypto"
	"encoding/binary"

	"crypto/sha512"
	"crypto/cipher"
	"crypto/aes"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

const v1_CLIENT_MASKED_ID_OFFSET = 4
const v1_CLIENT_DH_PUBLIC_OFFSET = 20
const v1_CLIENT_PACKET_LENGTH = 52

const v1_SERVER_MASKED_ID_OFFSET = 4
const v1_SERVER_MASKED_VALUE_OFFSET = 20
const v1_SERVER_AUTH_OFFSET = 28
const v1_SERVER_PACKET_LENGTH = 60

type serverX22519AESGCM128 struct {
	ServerPrivateKey []byte
}

type clientX25519AESGCM128 struct {
	ServerPublicKey []byte
	ClientPrivateKey []byte
	clientPublicKey []byte
	clientServerPublicKey []byte
}

func generateX22519Private(random io.Reader) (privateKey []byte, err error) {
	if random == nil {
		random = rand.Reader
	}
	
	var priv [32]byte

	_, err = io.ReadFull(random, priv[:])
	if err != nil {
		return nil, err
	}

	// Point values and scalars are represented little-endian.
	// Secret key scalars should have the properties 2^254 <= key < 2^255 and (key % 8) == 0
	// See RFC 7748, section 5
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	return priv[:], nil
}

func generateX22519Pair(random io.Reader) ([]byte, []byte, error) {
	priv, err := generateX22519Private(random)

	if err != nil {
		return nil, nil, err
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)

	return priv, pub, err
}

func kdfX25519AESGCM128(dhParam []byte, sharedSecret []byte) (key []byte, iv_c []byte, iv_s []byte) {
	dkfHash := sha512.New384()
	dkfHash.Write(dhParam)
	dkfHash.Write(sharedSecret)
	derivedBytes := dkfHash.Sum(nil)
	
	key = derivedBytes[:16]	
	iv_c = derivedBytes[16:32]
	iv_s = derivedBytes[32:]

	return
}

func (client *clientX25519AESGCM128) PackOutgoing(data []byte) (packetBytes []byte, replyHandler ReplyHandler, err error) {
	var dhParam, sharedSecret []byte

	var sessionSecret []byte

	if sessionSecret, err = generateX22519Private(nil); err != nil {
		return
	}

	requestHeader := header{0, CipherSuiteX25519AESGCM}

	if client.ClientPrivateKey != nil {
		requestHeader.Flags |= flagsClientAuth
		if client.clientPublicKey == nil {
			if client.clientPublicKey, err = curve25519.X25519(client.ClientPrivateKey, curve25519.Basepoint); err != nil {
				return
			}
			if client.clientServerPublicKey, err = curve25519.X25519(client.ClientPrivateKey, client.ServerPublicKey); err != nil {
				return
			}
		}
		if dhParam, err = curve25519.X25519(sessionSecret, client.clientPublicKey); err != nil {
			return
		}
		if sharedSecret, err = curve25519.X25519(sessionSecret, client.clientServerPublicKey); err != nil {
			return
		}

		extendedData := make([]byte, len(data)+64)
		copy(extendedData[:32], client.clientPublicKey)
		copy(extendedData[32:64], sessionSecret)
		copy(extendedData[64:], data)
		data = extendedData
	} else {
		if dhParam, err = curve25519.X25519(sessionSecret, curve25519.Basepoint); err != nil {
			return
		}
		if sharedSecret, err = curve25519.X25519(sessionSecret, client.ServerPublicKey); err != nil {
			return
		}
	}

	symetricKey, client_nonce, server_nonce := kdfX25519AESGCM128(dhParam, sharedSecret)
	
	var block cipher.Block
	var aesgcm cipher.AEAD
	
	if block, err = aes.NewCipher(symetricKey[:]); err != nil {
		return
	}
	if aesgcm, err = cipher.NewGCMWithNonceSize(block, 16); err != nil {
		return
	}
	
	ciphertext := aesgcm.Seal(nil, client_nonce, data, nil)

	packetBuffer := new(bytes.Buffer)
	
	if err = binary.Write(packetBuffer, binary.BigEndian, requestHeader); err != nil {
		return
	}

	packetBuffer.Write(dhParam)
	packetBuffer.Write(ciphertext)	
	
	// Construct reply context with DH param and shared secret

	replyHandler = func (replyPacketBytes []byte) (data []byte, err error) {
		var replyHeader header
		replyPacketBuffer := bytes.NewReader(replyPacketBytes)
		if err = binary.Read(replyPacketBuffer, binary.BigEndian, &replyHeader); err != nil {
			return
		}

		if (replyHeader.Flags & flagsReply) == 0 {
			err = &PSSSTError{"Packet is not a reply"}
			return
		}
		if ((client.clientPublicKey == nil) != ((replyHeader.Flags & flagsClientAuth) == 0)) {
			err = &PSSSTError{"Reply client auth mismatch"}
			return
		}
		if replyHeader.CipherSuite != CipherSuiteX25519AESGCM {
			err = &PSSSTError{"Unsuported cipher suite"}
			return
		}
		if !bytes.Equal(replyPacketBytes[4:36], dhParam) {
			err = &PSSSTError{"Request/reply mismatch"}
			return
		}
		
		data, err = aesgcm.Open(nil, server_nonce, replyPacketBytes[36:], nil)
		return
	}

	packetBytes = packetBuffer.Bytes()
	
	return
}



func (server *serverX22519AESGCM128) UnpackIncoming(packetBytes []byte) (data []byte, replyHandler ReplyHandler, clientPublicKey crypto.PublicKey, err error) {
	var requestHeader header
	packetBuffer := bytes.NewReader(packetBytes)
	if err = binary.Read(packetBuffer, binary.BigEndian, &requestHeader); err != nil {
		return
	}

	if (requestHeader.Flags & flagsReply) != 0 {
		err = &PSSSTError{"Packet is a reply"}
		return
	}

	hasClientAuth := ((requestHeader.Flags & flagsClientAuth) != 0)

	if requestHeader.CipherSuite != CipherSuiteX25519AESGCM {
		err = &PSSSTError{"Unsuported cipher suite"}
		return
	}

	dhParam := packetBytes[4:36]

	var sharedSecret []byte
	
	if sharedSecret, err = curve25519.X25519(server.ServerPrivateKey, dhParam); err != nil {
		return
	}
	
	symetricKey, client_nonce, server_nonce := kdfX25519AESGCM128(dhParam, sharedSecret)
		
	var block cipher.Block
	var aesgcm cipher.AEAD
	
	if block, err = aes.NewCipher(symetricKey[:]); err != nil {
		return
	}
	if aesgcm, err = cipher.NewGCMWithNonceSize(block, 16); err != nil {
		return
	}

	var payload []byte
	if payload, err = aesgcm.Open(nil, client_nonce, packetBytes[36:], nil); err != nil {
		return
	}
	
	if hasClientAuth {
		clientPublicKeyBytes := payload[:32]
		ephemeralKey := payload[32:64]
		var checkClient []byte
		
		if checkClient, err = curve25519.X25519(ephemeralKey, clientPublicKeyBytes); err != nil {
			return
		}
		if !bytes.Equal(checkClient, dhParam) {
			err = &PSSSTError{"Client authentication failed"}
			return
		}
		clientPublicKey = clientPublicKeyBytes
		data = payload[64:]
	} else {
		data = payload
	}

	replyHandler = func (data []byte) (reply []byte, err error) {
		replyHeader := header{flagsReply, CipherSuiteX25519AESGCM}
		if hasClientAuth {
			replyHeader.Flags |= flagsClientAuth
		}
		
		ciphertext := aesgcm.Seal(nil, server_nonce, data, nil)

		packetBuffer := new(bytes.Buffer)
	
		if err = binary.Write(packetBuffer, binary.BigEndian, replyHeader); err != nil {
			return
		}

		packetBuffer.Write(dhParam)
		packetBuffer.Write(ciphertext)

		reply = packetBuffer.Bytes()
		return
	}

	return
}
