package contracttest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// gateSourceDir is package gate's source, relative to this package.
const gateSourceDir = ".."

// TestContractRoutesMatchDocument checks the route table itself: every
// pattern Routes registers is an operation in the document, and every
// operation in the document is a pattern Routes registers. The patterns
// are read from routes.go's source (a ServeMux cannot list what it
// holds), then each is confirmed against the live mux, so the source
// reading cannot drift from what is actually served.
func TestContractRoutesMatchDocument(t *testing.T) {
	doc := loadContractDoc(t)
	var registered []string
	for _, r := range readGateSource(t).routes {
		registered = append(registered, r.pattern)
	}
	slices.Sort(registered)

	mux, ok := newTestGate(t).g.Routes().(*http.ServeMux)
	if !ok {
		t.Fatal("Routes no longer returns an *http.ServeMux; update this test's live check")
	}
	for _, pattern := range registered {
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, strings.NewReplacer("{id}", "some-id").Replace(path), nil)
		if _, got := mux.Handler(req); got != pattern {
			t.Errorf("routes.go registers %q but the live mux serves %s %s as %q", pattern, method, req.URL.Path, got)
		}
	}

	documented := documentedOperations(doc)
	for _, op := range registered {
		if !slices.Contains(documented, op) {
			t.Errorf("Routes serves %s, which %s does not describe", op, contractDocPath)
		}
	}
	for _, op := range documented {
		if !slices.Contains(registered, op) {
			t.Errorf("%s describes %s, which Routes does not serve", contractDocPath, op)
		}
	}
	if len(registered) == 0 {
		t.Fatal("read no route patterns from routes.go")
	}
}

// TestContractRequestBodiesMatchHandlers checks gate's own request
// types against the document: for every route, the JSON fields its
// handler decodes are exactly the properties the document's request
// body lists. TestContractEveryRoute sends this module's copies of
// those bodies, which cannot see a field added to a handler type; this
// test can, as package gate's own types could when the contract test
// lived there. The types are read from source, since they are
// unexported.
func TestContractRequestBodiesMatchHandlers(t *testing.T) {
	doc := loadContractDoc(t)
	src := readGateSource(t)
	checked := 0
	for _, r := range src.routes {
		method, path, _ := strings.Cut(r.pattern, " ")
		item := doc.Paths.Value(path)
		if item == nil || item.GetOperation(method) == nil {
			continue // TestContractRoutesMatchDocument reports it
		}
		op := item.GetOperation(method)
		var documented []string
		hasBody := op.RequestBody != nil && op.RequestBody.Value != nil
		if hasBody {
			media := op.RequestBody.Value.Content.Get("application/json")
			if media == nil || media.Schema == nil || media.Schema.Value == nil {
				t.Errorf("%s: %s documents a request body with no application/json schema", r.pattern, contractDocPath)
				continue
			}
			for name := range media.Schema.Value.Properties {
				documented = append(documented, name)
			}
			slices.Sort(documented)
		}

		typeName, decodes := src.decodes[r.handler]
		switch {
		case !decodes && hasBody:
			t.Errorf("%s: %s documents a request body, but %s decodes none", r.pattern, contractDocPath, r.handler)
		case decodes && !hasBody:
			t.Errorf("%s: %s decodes %s, but %s documents no request body", r.pattern, r.handler, typeName, contractDocPath)
		case decodes:
			st, ok := src.structs[typeName]
			if !ok {
				t.Errorf("%s: %s decodes %s, which is not a struct type in package gate", r.pattern, r.handler, typeName)
				continue
			}
			fields := structJSONFields(t, src.fset, st)
			if !slices.Equal(fields, documented) {
				t.Errorf("%s: %s decodes %s with fields %v, but %s documents %v", r.pattern, r.handler, typeName, fields, contractDocPath, documented)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("found no handler that decodes a request body")
	}
}

// gateSource is what these tests read from package gate's source.
type gateSource struct {
	// routes holds each mux.Handle/mux.HandleFunc call in Routes: its
	// pattern and the Gate method that serves it.
	routes []gateRoute
	// decodes maps a function's name to the type of the request body it
	// decodes with decodeJSONBody.
	decodes map[string]string
	// structs maps a struct type's name to its declaration.
	structs map[string]*ast.StructType
	fset    *token.FileSet
}

type gateRoute struct{ pattern, handler string }

// readGateSource parses package gate's non-test files, resolving the
// package's string constants (sessionPath and the rest) in route
// patterns.
func readGateSource(t *testing.T) gateSource {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(gateSourceDir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := gateSource{decodes: map[string]string{}, structs: map[string]*ast.StructType{}, fset: fset}
	consts := map[string]string{}
	var routes *ast.FuncDecl
	var funcs []*ast.FuncDecl
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						if d.Tok != token.CONST {
							continue
						}
						for i, id := range s.Names {
							if i >= len(s.Values) {
								continue
							}
							if lit, ok := s.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								v, err := strconv.Unquote(lit.Value)
								if err != nil {
									t.Fatal(err)
								}
								consts[id.Name] = v
							}
						}
					case *ast.TypeSpec:
						if st, ok := s.Type.(*ast.StructType); ok {
							src.structs[s.Name.Name] = st
						}
					}
				}
			case *ast.FuncDecl:
				funcs = append(funcs, d)
				if d.Name.Name == "Routes" && d.Recv != nil {
					routes = d
				}
			}
		}
	}
	if routes == nil {
		t.Fatal("no Routes method found in package gate")
	}
	for _, fn := range funcs {
		if fn.Name.Name == "decodeJSONBody" || fn.Body == nil {
			continue
		}
		if typeName, ok := decodedType(t, fset, fn); ok {
			src.decodes[fn.Name.Name] = typeName
		}
	}

	var eval func(ast.Expr) string
	eval = func(e ast.Expr) string {
		switch e := e.(type) {
		case *ast.BasicLit:
			v, err := strconv.Unquote(e.Value)
			if err != nil {
				t.Fatal(err)
			}
			return v
		case *ast.Ident:
			v, ok := consts[e.Name]
			if !ok {
				t.Fatalf("route pattern uses %s, which is not a string constant in package gate", e.Name)
			}
			return v
		case *ast.BinaryExpr:
			if e.Op == token.ADD {
				return eval(e.X) + eval(e.Y)
			}
		}
		t.Fatalf("cannot read route pattern at %s", fset.Position(e.Pos()))
		return ""
	}

	recv := ""
	if names := routes.Recv.List[0].Names; len(names) == 1 {
		recv = names[0].Name
	}
	ast.Inspect(routes.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(call.Args) != 2 {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "mux" {
			return true
		}
		pattern := eval(call.Args[0])
		var handlers []string
		ast.Inspect(call.Args[1], func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == recv {
					handlers = append(handlers, s.Sel.Name)
				}
			}
			return true
		})
		if len(handlers) != 1 {
			t.Fatalf("cannot tell which Gate method serves %s at %s", pattern, fset.Position(call.Pos()))
		}
		src.routes = append(src.routes, gateRoute{pattern: pattern, handler: handlers[0]})
		return true
	})
	return src
}

// decodedType returns the type of the request body fn decodes: the T of
// `var req T` behind its one decodeJSONBody(w, r, &req) call.
func decodedType(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl) (string, bool) {
	t.Helper()
	varTypes := map[string]string{}
	var decoded []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			if id, ok := n.Type.(*ast.Ident); ok {
				for _, name := range n.Names {
					varTypes[name.Name] = id.Name
				}
			}
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); !ok || id.Name != "decodeJSONBody" {
				return true
			}
			if len(n.Args) == 3 {
				if u, ok := n.Args[2].(*ast.UnaryExpr); ok && u.Op == token.AND {
					if id, ok := u.X.(*ast.Ident); ok {
						decoded = append(decoded, id.Name)
						return true
					}
				}
			}
			t.Fatalf("cannot read the body decodeJSONBody fills at %s", fset.Position(n.Pos()))
		}
		return true
	})
	switch len(decoded) {
	case 0:
		return "", false
	case 1:
		typeName, ok := varTypes[decoded[0]]
		if !ok {
			t.Fatalf("%s decodes into %s, which is not declared `var %s T` in that function", fn.Name.Name, decoded[0], decoded[0])
		}
		return typeName, true
	}
	t.Fatalf("%s decodes %d request bodies; this test reads one per handler", fn.Name.Name, len(decoded))
	return "", false
}

// structJSONFields returns the JSON names encoding/json gives st's
// fields, sorted.
func structJSONFields(t *testing.T, fset *token.FileSet, st *ast.StructType) []string {
	t.Helper()
	var names []string
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			t.Fatalf("embedded field at %s: this test does not read embedded fields", fset.Position(field.Pos()))
		}
		tag := ""
		if field.Tag != nil {
			v, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Fatal(err)
			}
			tag, _, _ = strings.Cut(reflect.StructTag(v).Get("json"), ",")
		}
		for _, id := range field.Names {
			switch {
			case !id.IsExported() || tag == "-":
			case tag != "":
				names = append(names, tag)
			default:
				names = append(names, id.Name)
			}
		}
	}
	slices.Sort(names)
	return names
}
