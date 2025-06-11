// Filename: internal/protocol/processor_test.go
package protocol

import (
	"bytes"
	"io"
	"sudosrv/pkg/sudosrv_proto"
	"testing"
)

func TestProcessor(t *testing.T) {
	t.Run("ClientToServerMessage", func(t *testing.T) {
		var network bytes.Buffer // Simulate the network buffer

		// Create a processor
		proc := NewProcessor(&network, &network)

		// Create a test message
		clientHello := &sudosrv_proto.ClientHello{ClientId: "test-client/1.0"}
		clientMsg := &sudosrv_proto.ClientMessage{
			Event: &sudosrv_proto.ClientMessage_HelloMsg{HelloMsg: clientHello},
		}

		// Write the message (client -> server)
		if err := proc.WriteClientMessage(clientMsg); err != nil {
			t.Fatalf("WriteClientMessage() failed: %v", err)
		}

		// Read the message
		readMsg, err := proc.ReadClientMessage()
		if err != nil {
			t.Fatalf("ReadClientMessage() failed: %v", err)
		}

		// Validate the content
		readHello := readMsg.GetHelloMsg()
		if readHello == nil {
			t.Fatal("Read message is not a ClientHello")
		}
		if readHello.ClientId != clientHello.ClientId {
			t.Errorf("expected client_id '%s', got '%s'", clientHello.ClientId, readHello.ClientId)
		}
	})

	t.Run("ServerToClientMessage", func(t *testing.T) {
		var network bytes.Buffer

		proc := NewProcessor(&network, &network)

		// Create a test message
		serverHello := &sudosrv_proto.ServerHello{ServerId: "test-server/1.0"}
		serverMsg := &sudosrv_proto.ServerMessage{
			Event: &sudosrv_proto.ServerMessage_Hello{Hello: serverHello},
		}

		// Write the message (server -> client)
		if err := proc.WriteServerMessage(serverMsg); err != nil {
			t.Fatalf("WriteServerMessage() failed: %v", err)
		}

		// Read the message
		readMsg, err := proc.ReadServerMessage()
		if err != nil {
			t.Fatalf("ReadServerMessage() failed: %v", err)
		}

		// Validate the content
		readHello := readMsg.GetHello()
		if readHello == nil {
			t.Fatal("Read message is not a ServerHello")
		}
		if readHello.ServerId != serverHello.ServerId {
			t.Errorf("expected server_id '%s', got '%s'", serverHello.ServerId, readHello.ServerId)
		}
	})

	t.Run("ReadErrorOnShortBuffer", func(t *testing.T) {
		// Provide a buffer that is too short (e.g., only 2 bytes for length prefix)
		network := bytes.NewBuffer([]byte{0x00, 0x01})
		proc := NewProcessor(network, io.Discard)

		_, err := proc.ReadClientMessage()
		if err == nil {
			t.Fatal("ReadClientMessage() should have failed on a short read, but it did not")
		}
	})

	t.Run("ReadErrorOnMessageTooLarge", func(t *testing.T) {
		// Provide a length prefix that exceeds the maxMessageSize
		// Length: 2MB + 1 byte
		network := bytes.NewBuffer([]byte{0x00, 0x20, 0x00, 0x01})
		proc := NewProcessor(network, io.Discard)

		_, err := proc.ReadClientMessage()
		if err == nil {
			t.Fatal("ReadClientMessage() should have failed on a message larger than the limit, but it did not")
		}
	})
}
