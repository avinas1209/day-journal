package core_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCoreDependsOnNothingOutside enforces the dependency rule of the
// hexagon: the core may import the standard library, its own packages, and
// small neutral helpers — never an adapter or an infrastructure driver.
//
// If this test fails, the fix is a new port, not a new import.
func TestCoreDependsOnNothingOutside(t *testing.T) {
	const modulePath = "github.com/avinas1209/day-journal"

	// Third-party packages the core is allowed to use. Keep this list short:
	// every addition is a piece of the outside world leaking inwards.
	allowed := map[string]bool{
		"github.com/google/uuid": true,
	}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			switch {
			case !strings.Contains(strings.SplitN(imp, "/", 2)[0], "."):
				// Standard library: no dot in the first path segment.
			case strings.HasPrefix(imp, modulePath+"/internal/core/"):
				// Another core package.
			case allowed[imp]:
			case strings.HasPrefix(imp, modulePath+"/internal/adapter/"):
				t.Errorf("%s imports the adapter %q: depend on a port instead", path, imp)
			default:
				t.Errorf("%s imports %q, which is outside the core", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk core: %v", err)
	}
}
