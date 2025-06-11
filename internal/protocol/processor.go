// Filename: internal/protocol/processor.go
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	pb "sudosrv/pkg/sudosrv_proto"

	"google.golang.org/protobuf/proto"
)

const maxMessageSize = 2 * 1024 * 1024 // 2MB, as per sudo_logsrv.proto spec

// Processor handles reading and writing length-prefixed protobuf messages.
type Processor interface {
	ReadClientMessage() (*pb.ClientMessage, error)
	WriteServerMessage(*pb.ServerMessage) error
	ReadServerMessage() (*pb.ServerMessage, error)
	WriteClientMessage(*pb.ClientMessage) error
}

type processor struct {
	reader   io.Reader
	writer   io.Writer
	writeMux sync.Mutex
}

// NewProcessor creates a new protocol processor.
func NewProcessor(r io.Reader, w io.Writer) Processor {
	return &processor{
		reader: r,
		writer: w,
	}
}

// readMessage is a generic helper to read a length-prefixed message.
func (p *processor) readMessage(reader io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > maxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds limit of %d", msgLen, maxMessageSize)
	}

	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(reader, msgBuf); err != nil {
		return nil, fmt.Errorf("failed to read message payload: %w", err)
	}

	return msgBuf, nil
}

// ReadClientMessage reads one length-prefixed message from the reader and unmarshals it.
func (p *processor) ReadClientMessage() (*pb.ClientMessage, error) {
	msgBuf, err := p.readMessage(p.reader)
	if err != nil {
		return nil, err
	}

	clientMsg := &pb.ClientMessage{}
	if err := proto.Unmarshal(msgBuf, clientMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ClientMessage: %w", err)
	}

	return clientMsg, nil
}

// ReadServerMessage reads one length-prefixed message and unmarshals it as a ServerMessage.
func (p *processor) ReadServerMessage() (*pb.ServerMessage, error) {
	msgBuf, err := p.readMessage(p.reader)
	if err != nil {
		return nil, err
	}

	serverMsg := &pb.ServerMessage{}
	if err := proto.Unmarshal(msgBuf, serverMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ServerMessage: %w", err)
	}

	return serverMsg, nil
}


// writeMessage is a generic helper to write a length-prefixed message.
func (p *processor) writeMessage(writer io.Writer, msg proto.Message) error {
	outBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(outBytes)))

	if _, err := writer.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}

	if _, err := writer.Write(outBytes); err != nil {
		return fmt.Errorf("failed to send message payload: %w", err)
	}
	return nil
}


// WriteServerMessage marshals a ServerMessage and writes it to the writer with a length prefix.
func (p *processor) WriteServerMessage(msg *pb.ServerMessage) error {
	p.writeMux.Lock()
	defer p.writeMux.Unlock()
	return p.writeMessage(p.writer, msg)
}

// WriteClientMessage marshals a ClientMessage and writes it to the writer with a length prefix.
func (p *processor) WriteClientMessage(msg *pb.ClientMessage) error {
	p.writeMux.Lock()
	defer p.writeMux.Unlock()
	return p.writeMessage(p.writer, msg)
}
