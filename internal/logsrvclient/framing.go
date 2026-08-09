// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/framing.go
package logsrvclient

import (
	"encoding/binary"
	"fmt"
	"io"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"

	"google.golang.org/protobuf/proto"
)

// WriteMessage serializes and writes a single ClientMessage with its length
// prefix, in the same 4-byte big-endian framing as the wire protocol. This is
// what makes a journal file a replayable transcript: the bytes on disk are the
// bytes that go on the socket.
//
// Length prefix and payload are combined into a single Write for atomicity -- a
// partial write (process crash, full disk) must not leave a length prefix
// without a payload, because the reader would then block or misparse the
// remainder of the journal.
func WriteMessage(w io.Writer, msg *pb.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxMessageSize {
		return fmt.Errorf("message too large: length %d exceeds limit of %d", len(data), protocol.MaxMessageSize)
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

// ReadMessage reads a single length-prefixed ClientMessage written by
// WriteMessage. The size ceiling is enforced on the way in as well as out, so a
// corrupt or truncated journal cannot make the reader allocate arbitrarily.
func ReadMessage(r io.Reader) (*pb.ClientMessage, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > protocol.MaxMessageSize {
		return nil, fmt.Errorf("journal message size %d exceeds limit of %d", msgLen, protocol.MaxMessageSize)
	}
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	msg := &pb.ClientMessage{}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
