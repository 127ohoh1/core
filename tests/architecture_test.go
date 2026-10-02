package tests

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The data plane (and the shared protocol) must never depend on control-plane
// packages: commercial concepts cannot leak into enforcement by accident.
func TestDataPlaneDoesNotImportControlPlane(t *testing.T) {
	const forbidden = "github.com/127ohoh1/core/controlplane"
	fset := token.NewFileSet()
	for _, root := range []string{"../dataplane", "../protocol", "../cmd/edge"} {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				t.Fatal(perr)
			}
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, forbidden) {
					t.Errorf("%s imports %s: the data plane must not depend on the control plane", path, imp.Path.Value)
				}
			}
			return nil
		})
	}
}
