// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/buildmatrix_test.go
package logshell

import (
	"strings"
	"testing"
)

// The generated pb.go is committed. Regenerating it while building a package
// needs protoc, which no RHEL-family repository carries, and risks producing a
// different file than the one committed -- the drift the CI protoc pin exists
// to prevent. Freshness is asserted in CI instead, where protoc is pinned to
// the version the committed file was generated with.
func TestNoRecipeRegeneratesProtobuf(t *testing.T) {
	for format, files := range recipeFiles {
		for _, f := range files {
			for line := range strings.SplitSeq(readPackaging(t, f), "\n") {
				code := strings.TrimSpace(line)
				if strings.HasPrefix(code, "#") {
					continue
				}
				if strings.Contains(code, "make proto") ||
					strings.Contains(code, "$(MAKE) proto") {
					t.Errorf("%s (%s) regenerates protobuf at package-build time: %s",
						f, format, code)
				}
			}
		}
	}
}

// protobuf-compiler is absent from UBI 9, UBI 10 and Rocky 9, so declaring it
// makes every RHEL-family target unbuildable. The RPM spec declared it without
// ever invoking protoc.
func TestNoRecipeRequiresProtobufCompiler(t *testing.T) {
	for _, f := range []string{
		"../../packaging/rpm/sudosrv.spec",
		"../../packaging/debian/control",
		"../../packaging/arch/PKGBUILD",
	} {
		for line := range strings.SplitSeq(readPackaging(t, f), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") {
				continue
			}
			if strings.Contains(code, "protobuf-compiler") ||
				strings.Contains(code, "'protobuf'") {
				t.Errorf("%s declares a protobuf compiler; the committed pb.go makes "+
					"it unnecessary and no RHEL-family repo provides it: %s", f, code)
			}
		}
	}
}
