package shamir

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
)

// an x/y pair
type pair struct {
	x, y byte
}

// polynomial represents a polynomial of arbitrary degree
type polynomial struct {
	coefficients []uint8
}

// makePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func makePolynomial(intercept, degree uint8) (polynomial, error) {
	// Create a wrapper
	p := polynomial{
		coefficients: make([]byte, degree+1),
	}

	// Ensure the intercept is set
	p.coefficients[0] = intercept

	// Assign random co-efficients to the polynomial
	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return p, err
	}

	return p, nil
}

// evaluate returns the value of the polynomial for the given x
func (p *polynomial) evaluate(x byte) byte {
	// Special case the origin
	if x == 0 {
		return p.coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = add(mult(out, x), coeff)
	}
	return out
}

// Lagrange interpolation
//
// Takes N sample points and returns the value at a given x using a lagrange interpolation.
func interpolate(points []pair, x byte) (value byte) {
	for i, a := range points {
		weight := byte(1)
		for j, b := range points {
			if i != j {
				top := x ^ b.x
				bottom := a.x ^ b.x
				factor := div(top, bottom)
				weight = mult(weight, factor)
			}
		}
		value = value ^ mult(weight, a.y)
	}
	return
}

// div divides two numbers in GF(2^8)
func div(a, b uint8) uint8 {
	if b == 0 {
		// leaks some timing information but we don't care anyways as this
		// should never happen, hence the panic
		panic("divide by zero")
	}

	var goodVal, zero uint8
	log_a := logTable[a]
	log_b := logTable[b]
	diff := (int(log_a) - int(log_b)) % 255
	if diff < 0 {
		diff += 255
	}

	ret := expTable[diff]

	// Ensure we return zero if a is zero but aren't subject to timing attacks
	goodVal = ret

	if subtle.ConstantTimeByteEq(a, 0) == 1 {
		ret = zero
	} else {
		ret = goodVal
	}

	return ret
}

// mult multiplies two numbers in GF(2^8)
func mult(a, b uint8) (out uint8) {
	var goodVal, zero uint8
	log_a := logTable[a]
	log_b := logTable[b]
	sum := (int(log_a) + int(log_b)) % 255

	ret := expTable[sum]

	// Ensure we return zero if either a or be are zero but aren't subject to
	// timing attacks
	goodVal = ret

	if subtle.ConstantTimeByteEq(a, 0) == 1 {
		ret = zero
	} else {
		ret = goodVal
	}

	if subtle.ConstantTimeByteEq(b, 0) == 1 {
		ret = zero
	} else {
		// This operation does not do anything logically useful. It
		// only ensures a constant number of assignments to thwart
		// timing attacks.
		goodVal = zero
	}

	return ret
}

// add combines two numbers in GF(2^8)
// This can also be used for subtraction since it is symmetric.
func add(a, b uint8) uint8 {
	return a ^ b
}

type writer struct {
	io.Writer
	writers      map[byte]io.Writer
	threshold    int
	bytesWritten int
}

func (w *writer) Write(p []byte) (int, error) {
	n := 0
	// Construct a random polynomial for each byte of the secret.
	// Because we are using a field of size 256, we can only represent
	// a single byte as the intercept of the polynomial, so we must
	// use a new polynomial for each byte.
	for _, val := range p {
		p, err := makePolynomial(val, uint8(w.threshold-1))
		if nil != err {
			return n, fmt.Errorf("failed to generate polynomial: %v", err)
		}

		// Generate a `parts` number of (x,y) pairs
		// We cheat by encoding the x value once as the final index,
		// so that it only needs to be stored once.
		for x, w := range w.writers {
			y := p.evaluate(uint8(x))
			_, err := w.Write([]byte{y})
			if nil != err {
				return n, fmt.Errorf("failed to write part: %v", err)
			}
		}
		n++
		w.bytesWritten += n
	}

	return n, nil
}

func NewWriter(parts, threshold int, factory func(x byte) (io.Writer, error)) (io.Writer, error) {
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}

	result := writer{writers: make(map[byte]io.Writer, parts), threshold: threshold}

	buf := make([]byte, 1)
	for len(result.writers) < parts {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		x := buf[0]

		if x == 0 {
			// We cannot use a zero x coordinate otherwise the y values would be the intercepts i.e. the secret value itself.
			continue
		}
		if _, exists := result.writers[buf[0]]; exists {
			continue
		}

		w, err := factory(buf[0])
		if nil != err {
			return nil, err
		}
		result.writers[buf[0]] = w
	}

	return &result, nil
}

// Split takes an arbitrarily long secret and generates a `parts`
// number of shares, `threshold` of which are required to reconstruct
// the secret. The parts and threshold must be at least 2, and less
// than 256. The returned shares are each one byte longer than the secret
// as they attach a tag used to reconstruct the secret.
func Split(secret []byte, parts, threshold int) (map[byte][]byte, error) {
	buffers := make(map[byte]*bytes.Buffer, parts)
	factory := func(x byte) (io.Writer, error) {
		buffers[x] = &bytes.Buffer{}
		return buffers[x], nil
	}
	s, err := NewWriter(parts, threshold, factory)
	if nil != err {
		return nil, fmt.Errorf("failed to initilize writer: %v", err)
	}

	if _, err := s.Write(secret); nil != err {
		return nil, fmt.Errorf("failed to split secret: %v", err)
	}

	out := make(map[byte][]byte, parts)
	for x, buf := range buffers {
		out[x] = buf.Bytes()
	}

	// Return the encoded secrets
	return out, nil
}

// Combine is used to reverse a Split and reconstruct a secret
// once a `threshold` number of parts are available.
func Combine(parts map[byte][]byte) ([]byte, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Verify the parts are all the same length
	var firstPartLen int
	for x := range parts {
		firstPartLen = len(parts[x])
		break
	}
	if firstPartLen < 1 {
		return nil, fmt.Errorf("parts must be at least one byte long")
	}
	for _, part := range parts {
		if len(part) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// Create a buffer to store the reconstructed secret
	secret := make([]byte, firstPartLen)
	points := make([]pair, len(parts))

	for i := range secret {
		p := 0
		for k, v := range parts {
			points[p] = pair{x: k, y: v[i]}
			p++
		}
		secret[i] = interpolate(points, 0)
	}

	return secret, nil
}

type reader struct {
	io.Reader
	readers map[byte]io.Reader
	eof     bool
}

func NewReader(readers map[byte]io.Reader) (io.Reader, error) {
	// Verify enough parts provided
	if len(readers) < 2 {
		return nil, fmt.Errorf("at least two parts are required to reconstruct the secret")
	}
	return &reader{readers: readers}, nil
}

func (r *reader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	points := make([][]pair, len(p))
	for i := range points {
		points[i] = make([]pair, len(r.readers))
	}

	j := 0
	n := 0

	for x, ir := range r.readers {
		buf := make([]byte, len(p))
		m, err := ir.Read(buf)
		if io.EOF == err {
			r.eof = true
		} else if nil != err {
			return 0, err
		} else if 0 != n && 0 != m && m != n {
			return 0, fmt.Errorf("input must be of equal length")
		}
		n = m

		for i := 0; i < m; i++ {
			points[i][j] = pair{x: x, y: buf[i]}
		}
		j++
	}

	for m := 0; m < n; m++ {
		p[m] = interpolate(points[m], 0)
	}

	return n, nil
}
