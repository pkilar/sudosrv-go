// SPDX-License-Identifier: Apache-2.0
// Filename: internal/protocol/infomsg_stringlist_test.go
package protocol

import (
	"encoding/json"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestEmptyStringListSurvivesAsAnEmptyArray is the whole reason StringList
// exists. Protobuf cannot distinguish an empty repeated field from an absent
// one -- both encode to nothing -- so a deliberately empty list arrives as a nil
// slice, and a nil slice marshals to JSON `null`. null claims the value is
// unknown; the sender said it was empty. C writes an empty array.
func TestEmptyStringListSurvivesAsAnEmptyArray(t *testing.T) {
	sent := &pb.InfoMessage{Key: "submitenv", Value: &pb.InfoMessage_Strlistval{
		Strlistval: &pb.InfoMessage_StringList{Strings: []string{}},
	}}
	wire, err := proto.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	var got pb.InfoMessage
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	// Precondition: the round trip really does erase the distinction. If this
	// ever stops being true the coercion is dead weight and should go.
	if got.GetStrlistval().GetStrings() != nil {
		t.Fatal("an empty repeated field survived the wire as non-nil; " +
			"StringList's reason for existing no longer holds")
	}

	m := InfoMsgsToMap([]*pb.InfoMessage{&got})
	list, ok := m["submitenv"].([]string)
	if !ok {
		t.Fatalf("submitenv is %T, want []string", m["submitenv"])
	}
	if list == nil {
		t.Error("submitenv is a nil slice; it will marshal to null, not []")
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"submitenv":[]}`; string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}

// TestPopulatedStringListIsUnchanged keeps the coercion from touching real data.
func TestPopulatedStringListIsUnchanged(t *testing.T) {
	m := InfoMsgsToMap([]*pb.InfoMessage{{
		Key: "runargv", Value: &pb.InfoMessage_Strlistval{
			Strlistval: &pb.InfoMessage_StringList{Strings: []string{"bash", "-c", "id"}},
		},
	}})
	got, _ := m["runargv"].([]string)
	if len(got) != 3 || got[0] != "bash" || got[2] != "id" {
		t.Errorf("runargv = %v, want [bash -c id]", got)
	}
}
