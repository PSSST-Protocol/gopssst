package main

import (
	"log"
	"net"
	"sync"
	"github.com/nickovs/gopssst"
)

const BUFFER_SIZE = 1024

func newBufferPool(packetSize int) *sync.Pool {
	return &sync.Pool{
		New: func() (interface {}) {
			return make([]byte, packetSize)
		},
	}
}

func main() {
	serverPrivateKey, serverPublicKey, err := gopssst.GenerateKeyPair(gopssst.CipherSuiteX25519AESGCM, nil)
	if err != nil {
		log.Panicf("Generate server key failed with %s", err)
	}

	serverPublicBytes, _ := serverPublicKey.([]byte)
	log.Printf("Loaded auth key. Public key is %x\n", serverPublicBytes)

	server, err := gopssst.NewServer(gopssst.CipherSuiteX25519AESGCM, serverPrivateKey)
	if err != nil {
		log.Panicf("Failed to create new server: %s", err)
	}

	packetSocket, err := net.ListenPacket("udp", ":45678")
	if err != nil {
		log.Fatal(err)
	}
	defer packetSocket.Close()

	bufferPool := newBufferPool(BUFFER_SIZE)

	var buf []byte
	
	for {
		// This would be better using a pool of buffers
		buf = bufferPool.Get().([]byte)
		n, addr, err := packetSocket.ReadFrom(buf)
		if err != nil {
			continue
		}
		go serve(addr, buf, n, packetSocket, server, bufferPool)
	}
}

func serve(addr net.Addr, buf []byte, packetSize int, packetSocket net.PacketConn, server gopssst.Server, bufferPool *sync.Pool) {
	receivedMessage, serverReplyHandler, _, err := server.UnpackIncoming(buf[:packetSize])
	if err != nil {
		log.Printf("Unpacking request key failed with %s", err)
		return
	}

	replyPacket, err := serverReplyHandler(receivedMessage)
	if err != nil {
		log.Printf("Packing reply packet failed with %s", err)
		return
	}

	packetSocket.WriteTo(replyPacket, addr)
	bufferPool.Put(buf)
}
