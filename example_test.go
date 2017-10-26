package shamir

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func ExampleSplit() {
	secret := []byte("Hello world")
	parts, err := Split(secret, 3, 2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to split secret: %v\n", err)
	}
	fmt.Println(len(parts))
	for _, part := range parts {
		fmt.Println(len(part))
	}
	// Output:
	// 3
	// 11
	// 11
	// 11
}

func ExampleCombine() {
	parts := map[byte][]byte{
		71: {209, 38, 210, 117, 87, 218, 213, 140, 119, 77, 90},
		79: {27, 174, 140, 114, 4, 236, 44, 189, 215, 25, 201},
	}
	secret, err := Combine(parts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to recombine secret: %v\n", err)
	}
	fmt.Println(string(secret))
	// Output:
	// Hello world
}

func ExampleNewWriter() {
	secret := []byte("Hello world")
	writers := make(map[byte]*bytes.Buffer, 3)
	writer, err := NewWriter(3, 2, func(x byte) (io.Writer, error) {
		writers[x] = &bytes.Buffer{}
		return writers[x], nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create secret writer: %v\n", err)
	}
	if _, err := writer.Write(secret); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write secret: %v\n", err)
	}
	fmt.Println(len(writers))
	for _, w := range writers {
		fmt.Println(w.Len())
	}
	// Output
	// 3
	// 11
	// 11
	// 11
}

func ExampleNewReader() {
	readers := map[byte]io.Reader{
		71: bytes.NewBuffer([]byte{209, 38, 210, 117, 87, 218, 213, 140, 119, 77, 90}),
		79: bytes.NewBuffer([]byte{27, 174, 140, 114, 4, 236, 44, 189, 215, 25, 201}),
	}

	reader, err := NewReader(readers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create secret reader: %v\n", err)
	}
	secret := make([]byte, 11)
	if _, err := reader.Read(secret); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read secret: %v\n", err)
	}
	fmt.Println(string(secret))
	// Output:
	// Hello world
}
