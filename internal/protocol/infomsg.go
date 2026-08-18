// SPDX-License-Identifier: Apache-2.0
// Filename: internal/protocol/infomsg.go
package protocol

import (
	"fmt"
	"log/slog"

	pb "sudosrv/pkg/sudosrv_proto"
)

// InfoMsgsToMap converts a slice of InfoMessage entries to a generic map keyed
// by InfoMessage.Key. Entries with empty keys are skipped (matching C
// sudo_logsrvd, which treats keyless entries as malformed). Strval, Numval, and
// Strlistval values are unwrapped to their underlying Go types (string, int64,
// []string). Unknown value variants are dropped (preserving forward-compat with
// future proto extensions) but logged at Debug so a new field doesn't quietly
// disappear from audit records.
func InfoMsgsToMap(infos []*pb.InfoMessage) map[string]any {
	out := make(map[string]any, len(infos))
	for _, info := range infos {
		key := info.GetKey()
		if key == "" {
			continue
		}
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			out[key] = v.Strval
		case *pb.InfoMessage_Numval:
			out[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			out[key] = StringList(v.Strlistval)
		default:
			slog.Debug("InfoMessage variant dropped (unknown type)",
				"key", key, "type", fmt.Sprintf("%T", v))
		}
	}
	return out
}

// StringList returns a list value that is never nil.
//
// Protobuf cannot tell an empty repeated field from an absent one: both encode
// to nothing, so a DELIBERATELY empty list -- submitenv, which logsh sends to
// state that no submit environment was recorded -- arrives as a nil slice. Left
// alone that marshals to JSON `null`, which claims the value is unknown rather
// than empty. C writes an empty array, and so must this.
func StringList(l *pb.InfoMessage_StringList) []string {
	if s := l.GetStrings(); s != nil {
		return s
	}
	return []string{}
}
