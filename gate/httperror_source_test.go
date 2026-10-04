package gate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoPlainHTTPErrorInSource is gauntlet #23's guard: every error
// Routes or Protect answers with is now an RFC 9457 problem+json body
// (writeProblem/writeUnauthorized/writeAuthError/writeBlankProblem),
// never the plain-text body http.Error or http.NotFound would write.
// Reads this package's own non-test source with go/parser, the same
// way gate/contracttest/source_test.go reads route patterns from it,
// rather than grepping: an AST call expression cannot be defeated by a
// reformatted import alias or a comment that happens to contain the
// text "http.Error".
func TestNoPlainHTTPErrorInSource(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" {
				return true
			}
			if sel.Sel.Name == "Error" || sel.Sel.Name == "NotFound" {
				t.Errorf("%s: calls http.%s -- every error body here must be a problem+json one (writeProblem/writeUnauthorized/writeAuthError/writeBlankProblem), not a plain-text one", fset.Position(call.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("read no source files in package gate")
	}
}
