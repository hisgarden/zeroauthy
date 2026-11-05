package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sort"
	"testing"
)

// cbor is a tiny test-only CBOR encoder for building parser inputs. It
// encodes int64, []byte, string, bool, nil, []any and map[int64]any /
// map[string]any (keys sorted for determinism).
func cbor(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0xf6}
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case int:
		return cbor(int64(x))
	case int64:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case uint64:
		return cborHead(0, x)
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []any:
		out := cborHead(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, cbor(e)...)
		}
		return out
	case map[int64]any:
		keys := make([]int64, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		out := cborHead(5, uint64(len(x)))
		for _, k := range keys {
			out = append(out, cbor(k)...)
			out = append(out, cbor(x[k])...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := cborHead(5, uint64(len(x)))
		for _, k := range keys {
			out = append(out, cbor(k)...)
			out = append(out, cbor(x[k])...)
		}
		return out
	}
	panic("cbor: unsupported test value")
}

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
}

// coseEC2 encodes an EC2 COSE key for the curve id and algorithm.
func coseEC2(crv, alg int64, x, y []byte) []byte {
	return cbor(map[int64]any{1: int64(2), 3: alg, -1: crv, -2: x, -3: y})
}

func coseOKP(alg int64, x []byte) []byte {
	return cbor(map[int64]any{1: int64(1), 3: alg, -1: int64(6), -2: x})
}

func coseRSA(alg int64, n, e []byte) []byte {
	return cbor(map[int64]any{1: int64(3), 3: alg, -1: n, -2: e})
}

func pad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func genEC(t testing.TB, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	size := (curve.Params().BitSize + 7) / 8
	return k, pad(k.X.Bytes(), size), pad(k.Y.Bytes(), size)
}

func genEd(t testing.TB) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func bigBytes(bits int, topSet bool) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	if !topSet {
		n = new(big.Int).Sub(n, big.NewInt(1))
	}
	n.SetBit(n, 0, 1)
	return n.Bytes()
}
