package main

import (
	"bytes"
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	
	"crypto/rand"
	
	"github.com/nickovs/gopssst"
)

var reader *bufio.Reader

func get_msg() (tag string, value []byte) {
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Panicf("Failed to read input line: %s", err)
	}

	parts := strings.Split(line, ":")

	_, err = fmt.Sscanf(parts[1], "%x", &value)

	tag = parts[0]
	
	return
}

func emit_msg(tag string, value []byte) {
	fmt.Printf("%s:%x\n", tag, value)
}

func reverse_slice(s []byte) {
	l := len(s)
	for i := 0; i < l/2; i++ {
		x, y := s[i], s[l-1-i]
		s[i], s[l-1-i] = y, x
	}
}

func main() {
	suite := gopssst.CipherSuiteX25519AESGCM
	
	reader = bufio.NewReader(os.Stdin)
	
	serverPrivateKey, serverPublicKey, err := gopssst.GenerateKeyPair(suite, nil)
	if err != nil {
		log.Panicf("Generate server key failed with %s", err)
	}

	serverPublicBytes, _ := serverPublicKey.([]byte)
	emit_msg("SERVER_KEY", serverPublicBytes)

	clientPrivateKey, clientPublicKey, err := gopssst.GenerateKeyPair(suite, nil)
	if err != nil {
		log.Panicf("Generate client key failed with %s", err)
	}

	clientPublicBytes, _ := clientPublicKey.([]byte)
	emit_msg("CLIENT_KEY", clientPublicBytes)

	server, err := gopssst.NewServer(suite, serverPrivateKey)
	if err != nil {
		log.Panicf("Failed to create new server: %s", err)
	}

	random := rand.Reader

	plaintext := make([]byte, 64)

	_, err = io.ReadFull(random, plaintext[:])
	if err != nil {
		log.Panicf("Failed to read random plaintext: %s", err)
	}

	emit_msg("PLAINTEXT", plaintext)	

	_ = server

	var remote_client_key, remote_plaintext []byte
	var client_reply_handler, auth_client_reply_handler gopssst.ReplyHandler
	var client_out_packet, auth_client_out_packet []byte

	replies := 0
	
	for replies < 2 {
		tag, value := get_msg()
		// fmt.Fprintf(os.Stderr, "Tag: %s, value: %x\n", tag, value)

		switch tag {
		case "SERVER_KEY":
			client, err := gopssst.NewClient(suite, value, nil)
			if err != nil {
				log.Panicf("Failed to create client: %s", err)
			}
			client_out_packet, client_reply_handler, err = client.PackOutgoing(plaintext)
			if err != nil {
				log.Panicf("Failed to pack outgoing client message: %s", err)
			}
			emit_msg("REQUEST", client_out_packet)
			auth_client, err := gopssst.NewClient(suite, value, clientPrivateKey)
			if err != nil {
				log.Panicf("Failed to create client: %s", err)
			}
			auth_client_out_packet, auth_client_reply_handler, err = auth_client.PackOutgoing(plaintext)
			if err != nil {
				log.Panicf("Failed to pack outgoing auth client message: %s", err)
			}
			emit_msg("REQUEST_AUTH", auth_client_out_packet)

			reverse_slice(plaintext)
			
		case "CLIENT_KEY":
			remote_client_key = value
		case "PLAINTEXT":
			remote_plaintext = value
		case "REQUEST":
			data, serverReplyHandler, clientAuthKey, err := server.UnpackIncoming(value)
			if err != nil {
				log.Panicf("Failed to unpack incoming client message: %s", err)
			}
			if !bytes.Equal(data, remote_plaintext) {
				log.Panicf("Request plaintext did not match")
			}
			if clientAuthKey != nil {
				log.Panicf("Request contained auth key")
			}
			reverse_slice(data)
			reply_packet, err := serverReplyHandler(data)
			if err != nil {
				log.Panicf("Failed to pack reply: %s", err)
			}
			emit_msg("REPLY", reply_packet)
		case "REQUEST_AUTH":
			data, serverReplyHandler, clientAuthKey, err := server.UnpackIncoming(value)
			if err != nil {
				log.Panicf("Failed to unpack incoming client message: %s", err)
			}
			if !bytes.Equal(data, remote_plaintext) {
				log.Panicf("Request plaintext did not match")
			}
			clientAuthBytes, ok := clientAuthKey.([]byte)
			if !ok {
				log.Panicf("Client auth key was not bytes: %s", err)
			}
			if !bytes.Equal(clientAuthBytes, remote_client_key) {
				log.Panicf("Request auth key did not match")
			}
			reverse_slice(data)
			reply_packet, err := serverReplyHandler(data)
			if err != nil {
				log.Panicf("Failed to pack reply: %s", err)
			}
			emit_msg("REPLY_AUTH", reply_packet)		
		case "REPLY":
			reply_data, err := client_reply_handler(value)
			if err != nil {
				log.Panicf("Failed to unpack reply: %s", err)
			}
			if !bytes.Equal(reply_data, plaintext) {
				log.Panicf("Reply data did not match: %s", err)
			}						
			replies += 1
			if replies == 2 {
				emit_msg("DONE", []byte{})
			}
		case "REPLY_AUTH":
			reply_data, err := auth_client_reply_handler(value)
			if err != nil {
				log.Panicf("Failed to unpack auth reply: %s", err)
			}
			if !bytes.Equal(reply_data, plaintext) {
				log.Panicf("Reply data did not match: %s", err)
			}						
			replies += 1
			if replies == 2 {
				emit_msg("DONE", []byte{})
			}
		case "DONE":
			// Pass
		default:
			log.Panicf("Unknown TAG: %s", tag)
		}
	}
	
}
