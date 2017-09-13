package shamir

import (
	"bytes"
	"io"
	"testing"
)

func TestSplit_invalid(t *testing.T) {
	secret := []byte("test")

	if _, err := Split(secret, 0, 0); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 2, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 1000, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 10, 1); err == nil {
		t.Fatalf("expect error")
	}
}

func TestSplit(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(out) != 5 {
		t.Fatalf("bad: %v", out)
	}

	for _, share := range out {
		if len(share) != len(secret) {
			t.Fatalf("bad: %v", out)
		}
	}
}

func TestCombine_invalid(t *testing.T) {
	// Not enough parts
	if _, err := Combine(nil); err == nil {
		t.Fatalf("should err")
	}

	// Mis-match in length
	parts := map[byte][]byte{
		42: []byte("foo"),
		24: []byte("ba"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	//Too short
	parts = map[byte][]byte{
		1: []byte(""),
		2: []byte(""),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}
}

func TestCombine(t *testing.T) {
	secret := []byte("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	keys := make([]byte, len(out))

	i := 0
	for k := range out {
		keys[i] = k
		i++
	}

	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := uint8(0); i < 5; i++ {
		for j := uint8(0); j < 5; j++ {
			if j == i {
				continue
			}
			for k := uint8(0); k < 5; k++ {
				if k == i || k == j {
					continue
				}
				parts := map[byte][]byte{
					keys[i]: out[keys[i]],
					keys[j]: out[keys[j]],
					keys[k]: out[keys[k]],
				}
				recomb, err := Combine(parts)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				if !bytes.Equal(recomb, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recomb, secret)
				}

				readers := map[byte]io.Reader{
					keys[i]: bytes.NewReader(out[keys[i]]),
					keys[j]: bytes.NewReader(out[keys[j]]),
					keys[k]: bytes.NewReader(out[keys[k]]),
				}

				r, err := NewReader(readers)
				if nil != err {
					t.Errorf("failed to create reader: %v", err)
				}
				recomb2 := make([]byte, len(secret))
				if _, err := r.Read(recomb2); nil != err {
					t.Errorf("failed to combine secret: %v", err)
				}
				if !bytes.Equal(recomb2, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recomb2, secret)
				}
			}
		}
	}
}

func TestField_Add(t *testing.T) {
	if out := add(16, 16); out != 0 {
		t.Fatalf("Bad: %v 16", out)
	}

	if out := add(3, 4); out != 7 {
		t.Fatalf("Bad: %v 7", out)
	}
}

func TestField_Mult(t *testing.T) {
	if out := mult(3, 7); out != 9 {
		t.Fatalf("Bad: %v 9", out)
	}

	if out := mult(3, 0); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := mult(0, 3); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}
}

func TestField_Divide(t *testing.T) {
	if out := div(0, 7); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := div(3, 3); out != 1 {
		t.Fatalf("Bad: %v 1", out)
	}

	if out := div(6, 3); out != 2 {
		t.Fatalf("Bad: %v 2", out)
	}
}

func TestPolynomial_Random(t *testing.T) {
	p, err := makePolynomial(42, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if p.coefficients[0] != 42 {
		t.Fatalf("bad: %v", p.coefficients)
	}
}

func TestPolynomial_Eval(t *testing.T) {
	p, err := makePolynomial(42, 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if out := p.evaluate(0); out != 42 {
		t.Fatalf("bad: %v", out)
	}

	out := p.evaluate(1)
	exp := add(42, mult(1, p.coefficients[1]))
	if out != exp {
		t.Fatalf("bad: %v %v %v", out, exp, p.coefficients)
	}
}

func TestInterpolate_Rand(t *testing.T) {
	for i := 0; i < 256; i++ {
		p, err := makePolynomial(uint8(i), 2)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		pairs := []pair{
			{x: 1, y: p.evaluate(1)},
			{x: 2, y: p.evaluate(2)},
			{x: 3, y: p.evaluate(3)},
		}

		out := interpolate(pairs, 0)
		if out != uint8(i) {
			t.Fatalf("Bad: %v %d", out, i)
		}
	}
}
