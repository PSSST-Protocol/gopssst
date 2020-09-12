package gopssst

import (
	"bytes"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		t.Errorf("Generate server key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	outgoingPacket, clientReplyHandler, err := client.PackOutgoing(testMessage)
	if err != nil {
		t.Errorf("Packing request packet failed with %s", err)
	}

	receivedMessage, serverReplyHandler, clientAuthKey, err := server.UnpackIncoming(outgoingPacket)
	if err != nil {
		t.Errorf("Unpacking request key failed with %s", err)
	}

	if clientAuthKey != nil {
		t.Errorf("Client auth found but not provided")
	}

	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Received message did not match")
	}

	replyPacket, err := serverReplyHandler(receivedMessage)
	if err != nil {
		t.Errorf("Packing reply packet failed with %s", err)
	}

	receivedReply, err := clientReplyHandler(replyPacket)
	if err != nil {
		t.Errorf("Unacking reply packet failed with %s", err)
	}

	if !bytes.Equal(testMessage, receivedReply) {
		t.Errorf("Round-trip reply did not match")
	}
}

func TestServerReplyReuse(t *testing.T) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		t.Errorf("Generate server key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	outgoingPacket, clientReplyHandler, err := client.PackOutgoing(testMessage)
	if err != nil {
		t.Errorf("Packing request packet failed with %s", err)
	}

	receivedMessage, serverReplyHandler, clientAuthKey, err := server.UnpackIncoming(outgoingPacket)
	if err != nil {
		t.Errorf("Unpacking request key failed with %s", err)
	}

	if clientAuthKey != nil {
		t.Errorf("Client auth found but not provided")
	}

	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Received message did not match")
	}

	// Try packing the replies twice
	replyPacket, err := serverReplyHandler(receivedMessage)
	if err != nil {
		t.Errorf("Packing reply packet failed with %s", err)
	}

	_, err = serverReplyHandler(receivedMessage)
	if err == nil {
		t.Errorf("Server reply handler alloowed packing twice")
	}

	_, err = clientReplyHandler(replyPacket)
	if err != nil {
		t.Errorf("Unacking reply packet failed with %s", err)
	}

	_, err = clientReplyHandler(replyPacket)
	if err == nil {
		t.Errorf("Client reply handler alloowed packing twice")
	}
}

func TestRoundtripClientAuth(t *testing.T) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		t.Errorf("Generate server key failed with %s", err)
	}

	clientPrivateKey, clientPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		t.Errorf("Generate client key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, clientPrivateKey)

	testMessage := []byte("This is a test!")

	outgoingPacket, clientReplyHandler, err := client.PackOutgoing(testMessage)
	if err != nil {
		t.Errorf("Packing request packet failed with %s", err)
	}

	receivedMessage, serverReplyHandler, clientAuthKey, err := server.UnpackIncoming(outgoingPacket)
	if err != nil {
		t.Errorf("Unpacking request key failed with %s", err)
	}

	clientAuthKeyBytes, ok := clientAuthKey.([]byte)
	if !ok {
		t.Errorf("Client auth key was not bytes")
	}

	clientPubKeyBytes, ok := clientPublicKey.([]byte)
	if !ok {
		t.Errorf("Client auth key was not bytes")
	}

	if !bytes.Equal(clientAuthKeyBytes, clientPubKeyBytes) {
		t.Errorf("Client auth did not match senders")
	}

	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Received message did not match")
	}

	replyPacket, err := serverReplyHandler(receivedMessage)
	if err != nil {
		t.Errorf("Packing reply packet failed with %s", err)
	}

	receivedReply, err := clientReplyHandler(replyPacket)
	if err != nil {
		t.Errorf("Unacking reply packet failed with %s", err)
	}

	if !bytes.Equal(testMessage, receivedReply) {
		t.Errorf("Round-trip reply did not match")
	}
}

func BenchmarkPackRequest(b *testing.B) {
	_, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
	}
}

func BenchmarkPackRequestClientAuth(b *testing.B) {
	_, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	clientPrivateKey, _, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate client key failed with %s", err)
	}

	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, clientPrivateKey)

	testMessage := []byte("This is a test!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
	}
}

func BenchmarkUnpackIncoming(b *testing.B) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	prebuilt := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		prebuilt[i], _, err = client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err = server.UnpackIncoming(prebuilt[i])
		if err != nil {
			b.Errorf("Unpacking request packet failed with: %s", err)
		}
	}
}

func BenchmarkUnpackIncomingClientAuth(b *testing.B) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	clientPrivateKey, _, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate client key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, clientPrivateKey)

	testMessage := []byte("This is a test!")

	prebuilt := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		prebuilt[i], _, err = client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err = server.UnpackIncoming(prebuilt[i])
		if err != nil {
			b.Errorf("Unpacking request packet failed with: %s", err)
		}
	}
}

func BenchmarkUnpackAndReply(b *testing.B) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	prebuilt := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		prebuilt[i], _, err = client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, handler, _, err := server.UnpackIncoming(prebuilt[i])
		if err != nil {
			b.Errorf("Unpacking request packet failed with: %s", err)
		}
		_, err = handler(data)
		if err != nil {
			b.Errorf("Making reply packet failed with: %s", err)
		}
	}
}

type prepackedReplies struct {
	replyPacket []byte
	handler     ReplyHandler
}

func BenchmarkUnpackReplyPacket(b *testing.B) {
	serverPrivateKey, serverPublicKey, err := GenerateKeyPair(CipherSuiteX25519AESGCM, nil)
	if err != nil {
		b.Errorf("Generate server key failed with %s", err)
	}

	server, _ := NewServer(CipherSuiteX25519AESGCM, serverPrivateKey)
	client, _ := NewClient(CipherSuiteX25519AESGCM, serverPublicKey, nil)

	testMessage := []byte("This is a test!")

	var prebuiltN int

	if b.N > 1000 {
		prebuiltN = 1000
	} else {
		prebuiltN = b.N
	}

	prebuilt := make([]prepackedReplies, prebuiltN)
	for i := 0; i < prebuiltN; i++ {
		requestPacket, clientReplyHandler, err := client.PackOutgoing(testMessage)
		if err != nil {
			b.Errorf("Making request packet failed with: %s", err)
		}
		_, serverReplyhandler, _, err := server.UnpackIncoming(requestPacket)
		if err != nil {
			b.Errorf("Unpacking request packet failed with: %s", err)
		}
		replyPacket, err := serverReplyhandler(testMessage)
		if err != nil {
			b.Errorf("Making reply packet failed with: %s", err)
		}
		prebuilt[i].replyPacket = replyPacket
		prebuilt[i].handler = clientReplyHandler
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packedEntry := prebuilt[i%prebuiltN]
		packet := packedEntry.replyPacket
		handler := packedEntry.handler
		_, err = handler(packet)
		if err != nil {
			b.Errorf("Unpacking reply packet failed with: %s", err)
		}
	}
}
