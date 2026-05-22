// Filename: internal/protocol/infomsg.go
package protocol

import pb "sudosrv/pkg/sudosrv_proto"

// InfoMsgsToMap converts a slice of InfoMessage entries to a generic map keyed
// by InfoMessage.Key. Entries with empty keys are skipped (matching C
// sudo_logsrvd, which treats keyless entries as malformed). Strval, Numval, and
// Strlistval values are unwrapped to their underlying Go types (string, int64,
// []string). Unknown value variants are silently dropped — this keeps the
// helper forward-compatible if the proto schema grows new InfoMessage value
// types in a future sudo release.
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
			out[key] = v.Strlistval.GetStrings()
		}
	}
	return out
}
