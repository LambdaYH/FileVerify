package verify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"

	"path/filepath"
	"strings"

	"testing"
)

func fixture(t *testing.T) *Engine {
	t.Helper()
	root := t.TempDir()
	e := New(root, filepath.Join(root, "FolderVerify.exe"))
	put(t, e, "FolderVerify.exe", "excluded executable")
	put(t, e, "中文 目录/config & file.txt", "original")
	put(t, e, "empty.bin", "")
	return e
}
func put(t *testing.T, e *Engine, path, data string) {
	t.Helper()
	p := filepath.Join(e.Root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func generate(t *testing.T, e *Engine) *Manifest {
	t.Helper()
	r := e.Generate(context.Background(), false)
	if !r.Complete || r.Counts()["ERROR"] > 0 {
		t.Fatalf("generation failed: %+v", r)
	}
	m, err := e.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func status(t *testing.T, r Result, key string, n int) {
	t.Helper()
	if r.Counts()[key] != n {
		t.Fatalf("expected %s=%d, got %+v", key, n, r)
	}
}
func TestFirstRunSHA512AndEmptyFile(t *testing.T) {
	e := fixture(t)
	mode, _, err := e.Detect()
	if err != nil || mode != "生成" {
		t.Fatal(mode, err)
	}
	m := generate(t, e)
	if len(m.Files) != 2 {
		t.Fatal(m)
	}
	for _, v := range m.Files {
		data, err := os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(v.Path)))
		if err != nil {
			t.Fatal(err)
		}
		h := sha512.Sum512(data)
		if v.SHA512 != hex.EncodeToString(h[:]) || v.Size != int64(len(data)) {
			t.Fatal(v)
		}
	}
	mode, _, err = e.Detect()
	if mode != "校验" || err != nil {
		t.Fatal(mode, err)
	}
}
func TestUnchangedAndManifestNeverModified(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	p := filepath.Join(e.Root, ManifestName)
	before, _ := os.ReadFile(p)
	info, _ := os.Stat(p)
	r := e.Verify(context.Background(), m)
	status(t, r, "PASS", 2)
	if r.Conclusion() != "通过" {
		t.Fatal(r)
	}
	after, _ := os.ReadFile(p)
	info2, _ := os.Stat(p)
	if !bytes.Equal(before, after) || !info.ModTime().Equal(info2.ModTime()) {
		t.Fatal("verification changed manifest")
	}
}
func TestModifiedMissingAdded(t *testing.T) {
	for _, kind := range []string{"MODIFIED", "MISSING", "ADDED"} {
		t.Run(kind, func(t *testing.T) {
			e := fixture(t)
			m := generate(t, e)
			switch kind {
			case "MODIFIED":
				put(t, e, "中文 目录/config & file.txt", "modified")
			case "MISSING":
				if err := os.Remove(filepath.Join(e.Root, "empty.bin")); err != nil {
					t.Fatal(err)
				}
			case "ADDED":
				put(t, e, "new.zip", "new")
			}
			r := e.Verify(context.Background(), m)
			status(t, r, kind, 1)
			if !r.Complete || r.Conclusion() != "不通过" {
				t.Fatal(r)
			}
		})
	}
}
func TestMovedAbsoluteRoot(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	newRoot := t.TempDir()
	for _, p := range []string{"FolderVerify.exe", ManifestName, "empty.bin", "中文 目录/config & file.txt"} {
		b, err := os.ReadFile(filepath.Join(e.Root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		put(t, New(newRoot, ""), p, string(b))
	}
	other := New(newRoot, filepath.Join(newRoot, "FolderVerify.exe"))
	r := other.Verify(context.Background(), m)
	if r.Conclusion() != "通过" {
		t.Fatal(r)
	}
}
func TestCorruptManifestDoesNotRegenerate(t *testing.T) {
	for _, body := range []string{"{broken", `{"version":2,"algorithm":"SHA-512","files":[]}`, `{"version":1,"version":2,"algorithm":"SHA-512","files":[]}`, `{"version":1,"algorithm":"SHA-512","files":null}`} {
		t.Run(body, func(t *testing.T) {
			e := fixture(t)
			put(t, e, ManifestName, body)
			mode, _, err := e.Detect()
			if mode != "校验" || err == nil {
				t.Fatal("invalid manifest must stop startup")
			}
			b, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
			if string(b) != body {
				t.Fatal("manifest overwritten")
			}
		})
	}
}
func TestTraversalRejected(t *testing.T) {
	e := fixture(t)
	h := strings.Repeat("0", 128)
	for _, p := range []string{"../outside", "C:/outside", "/outside", "dir/../outside", `dir\outside`, "a:stream", "CON", "dir/trailing.", "sha512-manifest.json"} {
		m := Manifest{1, "SHA-512", []Entry{{p, 0, h}}}
		b, _ := json.Marshal(m)
		put(t, e, ManifestName, string(b))
		if _, err := e.Load(); err == nil {
			t.Fatalf("unsafe path accepted: %s", p)
		}
	}
}
func TestCancellationNeverPublishesPartialManifest(t *testing.T) {
	e := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.BeforeRead = func(string) { cancel() }
	r := e.Generate(ctx, false)
	if r.Complete {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(e.Root, ManifestName)); !os.IsNotExist(err) {
		t.Fatal("partial manifest exists", err)
	}
	files, _ := filepath.Glob(filepath.Join(e.Root, ".folderverify-*"))
	if len(files) != 0 {
		t.Fatal(files)
	}
}
func TestCanceledRegenerationPreservesOldManifest(t *testing.T) {
	e := fixture(t)
	generate(t, e)
	before, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	ctx, cancel := context.WithCancel(context.Background())
	e.BeforeRead = func(string) { cancel() }
	r := e.Generate(ctx, true)
	after, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	if r.Complete || !bytes.Equal(before, after) {
		t.Fatal(r)
	}
}
func TestMutationDuringProcessingDetected(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	e.BeforeRead = func(p string) {
		if p == "empty.bin" {
			put(t, e, p, "changed")
		}
	}
	r := e.Verify(context.Background(), m)
	status(t, r, "ERROR", 1)
	if r.Conclusion() == "通过" {
		t.Fatal(r)
	}
}
func TestEndRescanDetectsLateChanges(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	once := false
	e.Progress = func(p Progress) {
		if !once && p.Done == 2 && p.Phase == "校验 SHA-512" {
			once = true
			put(t, e, "late.txt", "added while hashing")
		}
	}
	r := e.Verify(context.Background(), m)
	if r.Complete || r.Conclusion() != "校验未完成" {
		t.Fatal(r)
	}
}
func TestEmptyFolderAndDeterministicManifest(t *testing.T) {
	e := New(t.TempDir(), "")
	m := generate(t, e)
	if len(m.Files) != 0 {
		t.Fatal(m)
	}
	if r := e.Verify(context.Background(), m); r.Conclusion() != "通过" {
		t.Fatal(r)
	}
	e = fixture(t)
	generate(t, e)
	a, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	r := e.Generate(context.Background(), true)
	b, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	if !r.Complete || !bytes.Equal(a, b) {
		t.Fatal("output not deterministic", r)
	}
}
func TestReportsExcludedAndSafeExport(t *testing.T) {
	e := fixture(t)
	m := generate(t, e)
	r := e.Verify(context.Background(), m)
	if err := e.Export(r); err != nil {
		t.Fatal(err)
	}
	if r = e.Verify(context.Background(), m); r.Conclusion() != "通过" {
		t.Fatal(r)
	}
	put(t, e, "nested/verify-report.txt", "user file")
	r = e.Verify(context.Background(), m)
	status(t, r, "ADDED", 1)
}
func TestGenerationFailureDoesNotCommit(t *testing.T) {
	e := fixture(t)
	e.BeforeRead = func(p string) {
		if p == "empty.bin" {
			os.Remove(filepath.Join(e.Root, p))
		}
	}
	r := e.Generate(context.Background(), false)
	if r.Complete {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(e.Root, ManifestName)); !os.IsNotExist(err) {
		t.Fatal("failed generation published manifest")
	}
}
func TestNoImplicitOverwrite(t *testing.T) {
	e := fixture(t)
	generate(t, e)
	before, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	put(t, e, "new.txt", "new")
	r := e.Generate(context.Background(), false)
	after, _ := os.ReadFile(filepath.Join(e.Root, ManifestName))
	if r.Complete || !bytes.Equal(before, after) {
		t.Fatal(r)
	}
}
func TestLongUnicodePaths(t *testing.T) {
	e := fixture(t)
	p := strings.Repeat("长路径目录/", 30) + "中文.txt"
	full := longPath(filepath.Join(e.Root, filepath.FromSlash(p)))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("long"), 0600); err != nil {
		t.Fatal(err)
	}
	m := generate(t, e)
	r := e.Verify(context.Background(), m)
	if r.Conclusion() != "通过" {
		t.Fatal(r)
	}
}
