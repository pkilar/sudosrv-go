// SPDX-License-Identifier: Apache-2.0
// Filename: internal/protocol/processor.go
package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// MaxMessageSize is the maximum allowed length-prefixed protobuf message size
// (2 MiB), as per the sudo_logsrv.proto specification. Exported so downstream
// packages (relay, tests) can enforce the same limit without re-declaring it.
const MaxMessageSize = 2 * 1024 * 1024

// Processor handles reading and writing length-prefixed protobuf messages.
type Processor interface {
	ReadClientMessage() (*pb.ClientMessage, error)
	ReadClientMessageContext(context.Context) (*pb.ClientMessage, error)
	WriteServerMessage(*pb.ServerMessage) error
	WriteServerMessageContext(context.Context, *pb.ServerMessage) error
	ReadServerMessage() (*pb.ServerMessage, error)
	ReadServerMessageContext(context.Context) (*pb.ServerMessage, error)
	WriteClientMessage(*pb.ClientMessage) error
	WriteClientMessageContext(context.Context, *pb.ClientMessage) error
	Close() error
}

type processor struct {
	reader   io.Reader
	writer   io.Writer
	writeMux sync.Mutex
	closer   io.Closer // Optional closer for the underlying connection
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

// NewProcessor creates a new protocol processor.
func NewProcessor(r io.Reader, w io.Writer) Processor {
	return &processor{
		reader: r,
		writer: w,
	}
}

// NewProcessorWithCloser creates a new protocol processor with a closer for the underlying connection.
func NewProcessorWithCloser(r io.Reader, w io.Writer, c io.Closer) Processor {
	return &processor{
		reader: r,
		writer: w,
		closer: c,
	}
}

// withReadContext runs fn() and aborts the underlying read promptly when ctx
// is cancelled. For non-cancellable contexts (context.Background()), where
// ctx.Done() returns nil, the watcher goroutine is skipped entirely — this
// saves 2 channels + 1 goroutine per protocol message on the common hot path.
func withReadContext(ctx context.Context, reader io.Reader, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	setter, ok := reader.(readDeadlineSetter)
	// Skip the watcher when (a) the reader cannot enforce a deadline or
	// (b) the context cannot be cancelled. Either condition makes the
	// watcher pure overhead.
	if !ok || ctx.Done() == nil {
		err := fn()
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = setter.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	err := fn()
	close(done)
	<-watcherDone
	_ = setter.SetReadDeadline(time.Time{})
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// withWriteContext mirrors withReadContext for the write side; see that
// function's godoc for the hot-path short-circuit rationale.
func withWriteContext(ctx context.Context, writer io.Writer, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	setter, ok := writer.(writeDeadlineSetter)
	if !ok || ctx.Done() == nil {
		err := fn()
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = setter.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	err := fn()
	close(done)
	<-watcherDone
	_ = setter.SetWriteDeadline(time.Time{})
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func writeFull(writer io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := writer.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

// readMessage is a generic helper to read a length-prefixed message.
func (p *processor) readMessage(ctx context.Context, reader io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if err := withReadContext(ctx, reader, func() error {
		_, err := io.ReadFull(reader, lenBuf)
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > MaxMessageSize {
		return nil, fmt.Errorf("message size %d exceeds limit of %d", msgLen, MaxMessageSize)
	}

	msgBuf := make([]byte, msgLen)
	if err := withReadContext(ctx, reader, func() error {
		_, err := io.ReadFull(reader, msgBuf)
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to read message payload: %w", err)
	}

	return msgBuf, nil
}

// ReadClientMessage reads one length-prefixed message from the reader and unmarshals it.
func (p *processor) ReadClientMessage() (*pb.ClientMessage, error) {
	return p.ReadClientMessageContext(context.Background())
}

// ReadClientMessageContext reads one length-prefixed ClientMessage and aborts
// promptly when ctx is cancelled if the underlying reader supports deadlines.
func (p *processor) ReadClientMessageContext(ctx context.Context) (*pb.ClientMessage, error) {
	msgBuf, err := p.readMessage(ctx, p.reader)
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
	return p.ReadServerMessageContext(context.Background())
}

// ReadServerMessageContext reads one length-prefixed ServerMessage and aborts
// promptly when ctx is cancelled if the underlying reader supports deadlines.
func (p *processor) ReadServerMessageContext(ctx context.Context) (*pb.ServerMessage, error) {
	msgBuf, err := p.readMessage(ctx, p.reader)
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
func (p *processor) writeMessage(ctx context.Context, writer io.Writer, msg proto.Message) error {
	outBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if len(outBytes) > MaxMessageSize {
		return fmt.Errorf("outgoing message size %d exceeds limit of %d", len(outBytes), MaxMessageSize)
	}

	// Combine length prefix and payload into a single write for atomicity
	buf := make([]byte, 4+len(outBytes))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(outBytes)))
	copy(buf[4:], outBytes)

	if err := withWriteContext(ctx, writer, func() error {
		return writeFull(writer, buf)
	}); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	return nil
}

// WriteServerMessage marshals a ServerMessage and writes it to the writer with a length prefix.
func (p *processor) WriteServerMessage(msg *pb.ServerMessage) error {
	return p.WriteServerMessageContext(context.Background(), msg)
}

// WriteServerMessageContext marshals a ServerMessage and writes it with a
// length prefix, aborting promptly when ctx is cancelled if possible.
func (p *processor) WriteServerMessageContext(ctx context.Context, msg *pb.ServerMessage) error {
	p.writeMux.Lock()
	defer p.writeMux.Unlock()
	return p.writeMessage(ctx, p.writer, msg)
}

// WriteClientMessage marshals a ClientMessage and writes it to the writer with a length prefix.
func (p *processor) WriteClientMessage(msg *pb.ClientMessage) error {
	return p.WriteClientMessageContext(context.Background(), msg)
}

// WriteClientMessageContext marshals a ClientMessage and writes it with a
// length prefix, aborting promptly when ctx is cancelled if possible.
func (p *processor) WriteClientMessageContext(ctx context.Context, msg *pb.ClientMessage) error {
	p.writeMux.Lock()
	defer p.writeMux.Unlock()
	return p.writeMessage(ctx, p.writer, msg)
}

// Close closes the underlying connection if available.
func (p *processor) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}
