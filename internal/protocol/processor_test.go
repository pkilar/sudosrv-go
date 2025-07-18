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
			Type: &sudosrv_proto.ClientMessage_HelloMsg{HelloMsg: clientHello},
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
			Type: &sudosrv_proto.ServerMessage_Hello{Hello: serverHello},
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

	t.Run("NewProcessorWithCloser", func(t *testing.T) {
		var network bytes.Buffer
		mockCloser := &mockCloser{}

		proc := NewProcessorWithCloser(&network, &network, mockCloser)

		// Test that Close() calls the closer
		err := proc.Close()
		if err != nil {
			t.Fatalf("Close() failed: %v", err)
		}

		if !mockCloser.closed {
			t.Error("Close() should have called the closer")
		}
	})

	t.Run("CloseWithoutCloser", func(t *testing.T) {
		var network bytes.Buffer
		proc := NewProcessor(&network, &network)

		// Test that Close() works even without a closer
		err := proc.Close()
		if err != nil {
			t.Fatalf("Close() should not fail when no closer is provided: %v", err)
		}
	})

	t.Run("WriteErrorHandling", func(t *testing.T) {
		// Use a writer that always fails
		failingWriter := &failingWriter{}
		var dummyReader bytes.Buffer
		proc := NewProcessor(&dummyReader, failingWriter)

		clientMsg := &sudosrv_proto.ClientMessage{
			Type: &sudosrv_proto.ClientMessage_HelloMsg{
				HelloMsg: &sudosrv_proto.ClientHello{ClientId: "test"},
			},
		}

		err := proc.WriteClientMessage(clientMsg)
		if err == nil {
			t.Fatal("WriteClientMessage() should have failed with failing writer")
		}
	})

	t.Run("ConcurrentWrites", func(t *testing.T) {
		var network bytes.Buffer
		var dummyReader bytes.Buffer
		proc := NewProcessor(&dummyReader, &network)

		// Test concurrent writes to ensure mutex works
		done := make(chan bool, 2)

		writeMessage := func() {
			clientMsg := &sudosrv_proto.ClientMessage{
				Type: &sudosrv_proto.ClientMessage_HelloMsg{
					HelloMsg: &sudosrv_proto.ClientHello{ClientId: "test"},
				},
			}
			err := proc.WriteClientMessage(clientMsg)
			if err != nil {
				t.Errorf("WriteClientMessage() failed: %v", err)
			}
			done <- true
		}

		go writeMessage()
		go writeMessage()

		// Wait for both writes to complete
		<-done
		<-done
	})

	t.Run("InvalidProtobufData", func(t *testing.T) {
		// Create a buffer with valid length but invalid protobuf data
		invalidData := []byte{0x00, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF}
		network := bytes.NewBuffer(invalidData)
		proc := NewProcessor(network, io.Discard)

		_, err := proc.ReadClientMessage()
		if err == nil {
			t.Fatal("ReadClientMessage() should have failed with invalid protobuf data")
		}
	})
}

// Mock closer for testing
type mockCloser struct {
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

// Failing writer for testing error conditions
type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrShortWrite
}
