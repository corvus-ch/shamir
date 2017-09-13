package shamir

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

var hasGfsplit bool
var hasGfcombine bool
var secret = []byte{
	0xc0, 0x73, 0x62, 0x4a, 0xaf, 0x39, 0x78, 0x51,
	0x4e, 0xf8, 0x44, 0x3b, 0xb2, 0xa8, 0x59, 0xc7,
	0x5f, 0xc3, 0xcc, 0x6a, 0xf2, 0x6d, 0x5a, 0xaa,
}

func init() {
	hasGfsplit = hasCommand("gfsplit")
	hasGfcombine = hasCommand("gfcombine")
}

func hasCommand(name string) bool {
	cmd := exec.Command("command", "-v", name)
	cmd.Stderr = os.Stderr
	return nil == cmd.Run()
}

func TestGfsplit(t *testing.T) {
	if !hasGfsplit {
		t.Skip("Skipping because 'libgfshare' is not available.")
	}

	dir, err := ioutil.TempDir(os.TempDir(), "data")
	defer os.RemoveAll(dir)
	if err != nil {
		t.Fatal("failed to create temporary file")
	}

	secretFile, err := ioutil.TempFile(dir, "secret")
	if err != nil {
		t.Fatal("failed to create secret file")
	}
	if _, err := secretFile.Write(secret); err != nil {
		t.Fatalf("failed to write to secret file: %v", err)
	}
	secretFile.Close()

	split := exec.Command("gfsplit", "-n", "2", "-m", "3", secretFile.Name())
	split.Dir = dir
	if err := split.Run(); err != nil {
		t.Fatalf("failed to run gfsplitt: %v", err)
	}

	partNames, err := filepath.Glob(secretFile.Name() + ".*")
	if err != nil {
		t.Errorf("failed to lookup ouput from gfsplit: %v", err)
	}
	if len(partNames) != 3 {
		t.Errorf("found unexpected number of files: got %d expected 3", len(partNames))
	}

	parts := make(map[byte]io.Reader, 3)
	for _, name := range partNames {
		x, err := strconv.ParseUint(string(name[len(name)-3:]), 10, 8)
		if err != nil {
			t.Fatalf("failed to parse x coordinate of file %s: %v", name, err)
		}
		file, err := os.Open(name)
		if err != nil {
			t.Fatalf("failed to open file: %v", err)
		}
		parts[byte(x)] = file
	}

	reader, err := NewReader(parts)
	if err != nil {
		t.Fatalf("failed to create shamir reader: %v", err)
	}
	result, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to combine secret: %v", err)
	}

	if !bytes.Equal(secret, result) {
		t.Fatalf("unexpected result:\n\texpected: %v\n\tgot: %v", secret, result)
	}
}

func TestGfcombine(t *testing.T) {
	if !hasGfcombine {
		t.Skip("Skipping because 'libgfshare' is not available.")
	}

	dir, err := ioutil.TempDir(os.TempDir(), "data")
	defer os.RemoveAll(dir)
	if err != nil {
		t.Fatal("failed to create temporary file")
	}

	partFiles := make(map[byte]*os.File, 3)
	writer, err := NewWriter(3, 2, func(x byte) (io.Writer, error) {
		file, err := os.Create(fmt.Sprintf("%s/part.%03d", dir, x))
		partFiles[x] = file
		return file, err
	})
	if _, err := writer.Write(secret); err != nil {
		t.Fatalf("Failed to split secret: %v", err)
	}
	for _, part := range partFiles {
		part.Close()
	}

	secretFileName := fmt.Sprintf("%s/secret", dir)
	for i, fileA := range partFiles {
		for j, fileB := range partFiles {
			if i == j {
				continue
			}
			combine := exec.Command("gfcombine", "-o", secretFileName, fileA.Name(), fileB.Name())
			combine.Dir = dir
			if err := combine.Run(); err != nil {
				t.Fatalf("failed to combine %s and %s: %v", fileA.Name(), fileB.Name(), err)
			}
			secretFile, err := os.Open(secretFileName)
			if err != nil {
				t.Fatalf("failed to open secret file: %v", err)
			}
			result, err := ioutil.ReadAll(secretFile)
			if err != nil {
				t.Fatalf("failed to read secret file: %v", err)
			}
			if !bytes.Equal(secret, result) {
				t.Fatalf("unexpected result:\n\texpected: %v\n\tgot: %v", secret, result)
			}
			secretFile.Close()
			if err := os.Remove(secretFileName); err != nil {
				t.Fatalf("failed to clean up secret file: %v", err)
			}
		}
	}
}
