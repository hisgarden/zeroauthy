package webauthn

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// DecodeCBOR decodes one data item of the RFC 8949 subset WebAuthn needs:
// unsigned and negative integers (as int64), byte strings ([]byte), text
// strings (string, valid UTF-8), arrays ([]any), maps (map[any]any with
// int64 or string keys, no duplicates) and the simple values false, true
// and null (nil). Tags, floats, indefinite lengths, undefined and other
// simple values are refused. maxDepth bounds nesting (the top-level item is
// depth 1) and maxItems bounds the number of data items, containers
// included. Trailing bytes are an error. Every error carries reason "parse".
func DecodeCBOR(b []byte, maxDepth, maxItems int) (any, error) {
	d := &cborDecoder{in: b, maxDepth: maxDepth, maxItems: maxItems}
	v, err := d.item(1)
	if err != nil {
		return nil, err
	}
	if len(d.in) != 0 {
		return nil, fail(ReasonParse, "trailing bytes after cbor")
	}
	return v, nil
}

// DecodeCBORPrefix decodes the first data item of b with the default bounds
// and returns the bytes that follow it. It serves the parts of authenticator
// data (the COSE key and the extensions) that CBOR items delimit.
func DecodeCBORPrefix(b []byte) (any, []byte, error) {
	d := &cborDecoder{in: b, maxDepth: CBORDepth, maxItems: CBORItems}
	v, err := d.item(1)
	if err != nil {
		return nil, nil, err
	}
	return v, d.in, nil
}

type cborDecoder struct {
	in       []byte
	maxDepth int
	maxItems int
	items    int
}

// head reads the initial byte and the argument of the next data item. It
// refuses the reserved additional-information values and indefinite lengths.
func (d *cborDecoder) head() (major, info byte, arg uint64, err error) {
	if len(d.in) == 0 {
		return 0, 0, 0, fail(ReasonParse, "truncated cbor")
	}
	first := d.in[0]
	d.in = d.in[1:]
	major = first >> 5
	info = first & 0x1f
	switch {
	case info < 24:
		return major, info, uint64(info), nil
	case info == 24:
		if len(d.in) < 1 {
			return 0, 0, 0, fail(ReasonParse, "truncated cbor argument")
		}
		arg = uint64(d.in[0])
		d.in = d.in[1:]
	case info == 25:
		if len(d.in) < 2 {
			return 0, 0, 0, fail(ReasonParse, "truncated cbor argument")
		}
		arg = uint64(binary.BigEndian.Uint16(d.in))
		d.in = d.in[2:]
	case info == 26:
		if len(d.in) < 4 {
			return 0, 0, 0, fail(ReasonParse, "truncated cbor argument")
		}
		arg = uint64(binary.BigEndian.Uint32(d.in))
		d.in = d.in[4:]
	case info == 27:
		if len(d.in) < 8 {
			return 0, 0, 0, fail(ReasonParse, "truncated cbor argument")
		}
		arg = binary.BigEndian.Uint64(d.in)
		d.in = d.in[8:]
	default: // 28–30 reserved, 31 indefinite length or break
		return 0, 0, 0, fail(ReasonParse, "unsupported cbor additional information")
	}
	return major, info, arg, nil
}

// item decodes one data item. depth is the number of containers that
// enclose it plus one; a container deeper than maxDepth is refused.
func (d *cborDecoder) item(depth int) (any, error) {
	d.items++
	if d.items > d.maxItems {
		return nil, fail(ReasonParse, "too many cbor items")
	}
	major, info, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned integer
		if arg > math.MaxInt64 {
			return nil, fail(ReasonParse, "cbor integer out of range")
		}
		return int64(arg), nil
	case 1: // negative integer: -1 - arg
		if arg > math.MaxInt64 {
			return nil, fail(ReasonParse, "cbor integer out of range")
		}
		return -1 - int64(arg), nil
	case 2: // byte string
		if arg > uint64(len(d.in)) {
			return nil, fail(ReasonParse, "truncated cbor byte string")
		}
		out := make([]byte, int(arg))
		copy(out, d.in[:arg])
		d.in = d.in[arg:]
		return out, nil
	case 3: // text string
		if arg > uint64(len(d.in)) {
			return nil, fail(ReasonParse, "truncated cbor text string")
		}
		raw := d.in[:arg]
		if !utf8.Valid(raw) {
			return nil, fail(ReasonParse, "cbor text is not utf-8")
		}
		d.in = d.in[arg:]
		return string(raw), nil
	case 4: // array: every element takes at least one byte
		if depth > d.maxDepth {
			return nil, fail(ReasonParse, "cbor nesting too deep")
		}
		if arg > uint64(len(d.in)) || arg > uint64(d.maxItems) {
			return nil, fail(ReasonParse, "truncated cbor array")
		}
		out := make([]any, 0, int(arg))
		for range arg {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map: every pair takes at least two bytes
		if depth > d.maxDepth {
			return nil, fail(ReasonParse, "cbor nesting too deep")
		}
		if arg > uint64(len(d.in))/2 || arg > uint64(d.maxItems) {
			return nil, fail(ReasonParse, "truncated cbor map")
		}
		out := make(map[any]any, int(arg))
		for range arg {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fail(ReasonParse, "cbor map key is not an integer or text")
			}
			if _, dup := out[k]; dup {
				return nil, fail(ReasonParse, "duplicate cbor map key")
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7: // simple values in one byte only; floats (25–27), undefined (23) and the one-byte extension (24) refused
		if info < 24 {
			switch arg {
			case 20:
				return false, nil
			case 21:
				return true, nil
			case 22:
				return nil, nil
			}
		}
		return nil, fail(ReasonParse, "unsupported cbor simple value or float")
	}
	return nil, fail(ReasonParse, "unsupported cbor tag")
}
