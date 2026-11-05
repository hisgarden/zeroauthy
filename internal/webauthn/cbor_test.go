package webauthn_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

func TestCBORSubset(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   []byte
			want any
		}{
			{"zero", []byte{0x00}, int64(0)},
			{"small", []byte{0x17}, int64(23)},
			{"one byte", []byte{0x18, 0xff}, int64(255)},
			{"two bytes", []byte{0x19, 0x01, 0x00}, int64(256)},
			{"four bytes", []byte{0x1a, 0x00, 0x01, 0x00, 0x00}, int64(65536)},
			{"eight bytes", []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 1}, int64(1)},
			{"max int64", cbor(uint64(1<<63 - 1)), int64(1<<63 - 1)},
			{"negative one", []byte{0x20}, int64(-1)},
			{"negative", []byte{0x38, 0x63}, int64(-100)},
			{"min int64", []byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, int64(-1 << 63)},
			{"bytes", []byte{0x43, 1, 2, 3}, []byte{1, 2, 3}},
			{"empty bytes", []byte{0x40}, []byte{}},
			{"text", []byte{0x62, 'h', 'i'}, "hi"},
			{"empty text", []byte{0x60}, ""},
			{"array", []byte{0x82, 0x01, 0x62, 'o', 'k'}, []any{int64(1), "ok"}},
			{"empty array", []byte{0x80}, []any{}},
			{"map int keys", cbor(map[int64]any{1: int64(2), -1: "x"}), map[any]any{int64(1): int64(2), int64(-1): "x"}},
			{"map text keys", cbor(map[string]any{"fmt": "none", "b": []byte{9}}), map[any]any{"fmt": "none", "b": []byte{9}}},
			{"empty map", []byte{0xa0}, map[any]any{}},
			{"false", []byte{0xf4}, false},
			{"true", []byte{0xf5}, true},
			{"null", []byte{0xf6}, nil},
			{"nested", cbor(map[string]any{"a": []any{int64(1), map[int64]any{2: nil}}}), map[any]any{"a": []any{int64(1), map[any]any{int64(2): nil}}}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := webauthn.DecodeCBOR(tc.in, webauthn.CBORDepth, webauthn.CBORItems)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("got %#v want %#v", got, tc.want)
				}
			})
		}
	})
	deep := func(n int) []byte {
		out := []byte{0x00}
		for range n {
			out = append([]byte{0x81}, out...)
		}
		return out
	}
	many := func(n int) []byte {
		out := cborHead(4, uint64(n))
		for range n {
			out = append(out, 0x01)
		}
		return out
	}
	t.Run("refused", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   []byte
		}{
			{"empty", nil},
			{"tag", []byte{0xc0, 0x00}},
			{"tag inside array", []byte{0x81, 0xd8, 0x18, 0x00}},
			{"half float", []byte{0xf9, 0x3c, 0x00}},
			{"single float", []byte{0xfa, 0, 0, 0, 0}},
			{"double float", []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}},
			{"indefinite bytes", []byte{0x5f, 0x41, 0x01, 0xff}},
			{"indefinite text", []byte{0x7f, 0x61, 'a', 0xff}},
			{"indefinite array", []byte{0x9f, 0x00, 0xff}},
			{"indefinite map", []byte{0xbf, 0x00, 0x00, 0xff}},
			{"break", []byte{0xff}},
			{"undefined", []byte{0xf7}},
			{"simple value byte", []byte{0xf8, 0x20}},
			{"reserved 28", []byte{0x1c}},
			{"duplicate int keys", []byte{0xa2, 0x01, 0x00, 0x01, 0x00}},
			{"duplicate text keys", []byte{0xa2, 0x61, 'a', 0x00, 0x61, 'a', 0x01}},
			{"bytes key", []byte{0xa1, 0x41, 0x01, 0x00}},
			{"array key", []byte{0xa1, 0x80, 0x00}},
			{"trailing bytes", []byte{0x00, 0x00}},
			{"truncated bytes", []byte{0x43, 1, 2}},
			{"truncated text", []byte{0x62, 'a'}},
			{"truncated array", []byte{0x82, 0x00}},
			{"truncated map", []byte{0xa1, 0x00}},
			{"truncated length", []byte{0x19, 0x01}},
			{"huge length", []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
			{"huge array length", []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
			{"uint above int64", []byte{0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0}},
			{"negative below int64", []byte{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0}},
			{"invalid utf8", []byte{0x61, 0xff}},
			{"depth 17", deep(17)},
			{"items 1025", many(1024)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := webauthn.DecodeCBOR(tc.in, webauthn.CBORDepth, webauthn.CBORItems)
				if err == nil {
					t.Fatal("accepted")
				}
				if r := webauthn.Reason(err); r != "parse" {
					t.Fatalf("reason %q want parse", r)
				}
			})
		}
	})
	t.Run("bounds", func(t *testing.T) {
		if _, err := webauthn.DecodeCBOR(deep(16), webauthn.CBORDepth, webauthn.CBORItems); err != nil {
			t.Fatalf("depth 16: %v", err)
		}
		if _, err := webauthn.DecodeCBOR(many(1023), webauthn.CBORDepth, webauthn.CBORItems); err != nil {
			t.Fatalf("items 1024: %v", err)
		}
		if _, err := webauthn.DecodeCBOR(deep(3), 2, webauthn.CBORItems); err == nil {
			t.Fatal("custom depth not enforced")
		}
		if _, err := webauthn.DecodeCBOR(many(3), webauthn.CBORDepth, 3); err == nil {
			t.Fatal("custom items not enforced")
		}
	})
	t.Run("prefix", func(t *testing.T) {
		in := append(cbor(map[int64]any{1: int64(2)}), 0xde, 0xad)
		v, rest, err := webauthn.DecodeCBORPrefix(in)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(v, map[any]any{int64(1): int64(2)}) || !bytes.Equal(rest, []byte{0xde, 0xad}) {
			t.Fatalf("got %#v rest %x", v, rest)
		}
		if _, _, err := webauthn.DecodeCBORPrefix(nil); err == nil {
			t.Fatal("empty prefix accepted")
		}
		if _, _, err := webauthn.DecodeCBORPrefix(deep(17)); err == nil {
			t.Fatal("deep prefix accepted")
		}
	})
}

func FuzzDecodeCBOR(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0xa2, 0x01, 0x02, 0x03, 0x26})
	f.Add(cbor(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": make([]byte, 37)}))
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00})
	f.Add([]byte{0xf9, 0x3c, 0x00})
	f.Add([]byte{0x5f, 0x41, 0x01, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := webauthn.DecodeCBOR(in, webauthn.CBORDepth, webauthn.CBORItems)
		if err != nil {
			if webauthn.Reason(err) != "parse" {
				t.Fatalf("reason %q", webauthn.Reason(err))
			}
			return
		}
		if v == nil && !bytes.Equal(in, []byte{0xf6}) {
			t.Fatalf("nil value for %x", in)
		}
		pv, rest, perr := webauthn.DecodeCBORPrefix(in)
		if perr != nil || len(rest) != 0 || !reflect.DeepEqual(pv, v) {
			t.Fatalf("prefix disagrees: %v rest=%x", perr, rest)
		}
	})
}
