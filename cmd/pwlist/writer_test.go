package main

import (
	"os"
	"path/filepath"
	"testing"
)

// buildInto runs the real `build` command, as TestBuildCommandWiring does,
// against a fake range API, writing the list to out.
func buildInto(t *testing.T, out string) {
	t.Helper()
	srv := newRangeServer(t, variedCorpus(12))
	cp := filepath.Join(t.TempDir(), "cp.json")
	code, _, stderr := runCLI(t, "build", "--base-url", srv.URL+"/range/", "--prefixes", "12",
		"--concurrency", "4", "--out", out, "--checkpoint", cp)
	if code != 0 {
		t.Fatalf("build: exit %d\n%s", code, stderr)
	}
}

// #90 item 15: the list writer creates a missing output directory, private
// to its owner, and the files in it keep their modes.
func TestBuildCreatesAMissingOutputDirectoryPrivately(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lists")
	out := filepath.Join(dir, "top10k.txt")
	buildInto(t, out)

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the output directory was not created: %v", err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("output directory is %v, want a directory with mode 0700", fi.Mode())
	}
	for _, name := range []string{"top10k.txt", "top10k.txt.sha256"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v, want 0644", name, fi.Mode().Perm())
		}
	}
}

// Replacing an existing list keeps the modes of the files it replaces,
// and leaves no temporary file behind.
func TestBuildOverExistingOutputKeepsModes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "top10k.txt")
	buildInto(t, out)
	buildInto(t, out)
	for _, name := range []string{"top10k.txt", "top10k.txt.sha256"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v after a rebuild, want 0644", name, fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("output directory holds %v, want just the list and its checksum", names)
	}
}
