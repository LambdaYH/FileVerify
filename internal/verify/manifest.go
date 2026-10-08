package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

func validPath(p string) bool {
	if p == "" || !utf8.ValidString(p) || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\:\x00") || path.Clean(p) != p {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." || strings.TrimRight(s, " .") != s || strings.ContainsAny(s, "<>\"|?*") {
			return false
		}
		for _, r := range s {
			if r < 32 {
				return false
			}
		}
		stem := strings.ToUpper(strings.Split(s, ".")[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" {
			return false
		}
		runes := []rune(stem)
		if len(runes) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && strings.ContainsRune("123456789¹²³", runes[3]) {
			return false
		}
	}
	return true
}

// Reject duplicate JSON members, including ambiguous version/path/hash values.
func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	v, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if v == '{' {
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			if err != nil {
				return err
			}
			k := t.(string)
			if seen[k] {
				return fmt.Errorf("重复 JSON 字段：%s", k)
			}
			seen[k] = true
			if err = uniqueJSON(d); err != nil {
				return err
			}
		}
	} else if v == '[' {
		for d.More() {
			if err = uniqueJSON(d); err != nil {
				return err
			}
		}
	} else {
		return errors.New("无效 JSON")
	}
	_, err = d.Token()
	return err
}
func (e *Engine) Load() (*Manifest, error) {
	f, cleanup, err := e.safeOpen(ManifestName)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 128*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 128*1024*1024 {
		return nil, errors.New("清单超过 128 MiB 安全上限")
	}
	if err = uniqueJSON(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var m Manifest
	if err = d.Decode(&m); err != nil {
		return nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("清单包含多余 JSON 内容")
	}
	if m.Version != 1 || m.Algorithm != "SHA-512" || m.Files == nil {
		return nil, errors.New("清单版本、算法或 files 字段不受支持")
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		key := strings.ToLower(f.Path)
		if !validPath(f.Path) || e.excluded(f.Path) || seen[key] || f.Size < 0 {
			return nil, fmt.Errorf("非法或重复清单路径：%q", f.Path)
		}
		seen[key] = true
		h, err := hex.DecodeString(f.SHA512)
		if err != nil || len(h) != 64 {
			return nil, fmt.Errorf("无效 SHA-512：%s", f.Path)
		}
	}
	return &m, nil
}
func (e *Engine) Detect() (string, *Manifest, error) {
	_, err := os.Lstat(longPath(e.Root + string(os.PathSeparator) + ManifestName))
	if os.IsNotExist(err) {
		return "生成", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	m, err := e.Load()
	return "校验", m, err
}
