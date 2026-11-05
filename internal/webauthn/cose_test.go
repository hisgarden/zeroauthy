package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

func TestCOSEKeys(t *testing.T) {
	_, edPub := genEd(t)
	p256, x256, y256 := genEC(t, elliptic.P256())
	_, x384, y384 := genEC(t, elliptic.P384())
	_, x521, y521 := genEC(t, elliptic.P521())
	n2048 := bigBytes(2048, true)
	n8192 := bigBytes(8192, true)
	e := []byte{0x01, 0x00, 0x01}

	t.Run("accepted", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			raw  []byte
			alg  int64
			kind any
		}{
			{"okp ed25519", coseOKP(-8, edPub), -8, ed25519.PublicKey(nil)},
			{"ec2 p256", coseEC2(1, -7, x256, y256), -7, (*ecdsa.PublicKey)(nil)},
			{"ec2 p384", coseEC2(2, -35, x384, y384), -35, (*ecdsa.PublicKey)(nil)},
			{"ec2 p521", coseEC2(3, -36, x521, y521), -36, (*ecdsa.PublicKey)(nil)},
			{"rsa 2048 pkcs1", coseRSA(-257, n2048, e), -257, (*rsa.PublicKey)(nil)},
			{"rsa 8192 pss", coseRSA(-37, n8192, e), -37, (*rsa.PublicKey)(nil)},
			{"rsa exponent 3", coseRSA(-257, n2048, []byte{3}), -257, (*rsa.PublicKey)(nil)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pk, err := webauthn.ParseCOSEKey(tc.raw)
				if err != nil {
					t.Fatal(err)
				}
				if pk.Alg != tc.alg {
					t.Fatalf("alg %d want %d", pk.Alg, tc.alg)
				}
				switch want := tc.kind.(type) {
				case ed25519.PublicKey:
					if _, ok := pk.Key.(ed25519.PublicKey); !ok {
						t.Fatalf("key %T", pk.Key)
					}
				case *ecdsa.PublicKey:
					got, ok := pk.Key.(*ecdsa.PublicKey)
					if !ok {
						t.Fatalf("key %T", pk.Key)
					}
					if tc.alg == -7 && !got.Equal(&p256.PublicKey) {
						t.Fatal("p256 key differs")
					}
					_ = want
				case *rsa.PublicKey:
					got, ok := pk.Key.(*rsa.PublicKey)
					if !ok {
						t.Fatalf("key %T", pk.Key)
					}
					if got.E != 65537 && got.E != 3 {
						t.Fatalf("exponent %d", got.E)
					}
					if bits := got.N.BitLen(); bits != 2048 && bits != 8192 {
						t.Fatalf("modulus %d bits", bits)
					}
				}
			})
		}
	})

	yOff := append([]byte(nil), y256...)
	yOff[len(yOff)-1] ^= 1
	bigKey := coseRSA(-257, make([]byte, webauthn.COSEMax), e)
	t.Run("refused", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			raw    []byte
			reason string
		}{
			{"empty", nil, "parse"},
			{"not cbor", []byte{0xff}, "parse"},
			{"not a map", cbor([]any{int64(1)}), "key"},
			{"text label", cbor(map[string]any{"kty": "EC"}), "key"},
			{"missing kty", cbor(map[int64]any{3: int64(-7)}), "key"},
			{"unknown kty", cbor(map[int64]any{1: int64(4), 3: int64(-7)}), "key"},
			{"unknown label", cbor(map[int64]any{1: int64(1), 3: int64(-8), -1: int64(6), -2: edPub, 2: []byte("kid")}), "key"},
			{"okp private d", cbor(map[int64]any{1: int64(1), 3: int64(-8), -1: int64(6), -2: edPub, -4: make([]byte, 32)}), "key"},
			{"ec2 private d", cbor(map[int64]any{1: int64(2), 3: int64(-7), -1: int64(1), -2: x256, -3: y256, -4: make([]byte, 32)}), "key"},
			{"rsa private d", cbor(map[int64]any{1: int64(3), 3: int64(-257), -1: n2048, -2: e, -3: n2048}), "key"},
			{"okp wrong curve", cbor(map[int64]any{1: int64(1), 3: int64(-8), -1: int64(7), -2: edPub}), "key"},
			{"okp short x", coseOKP(-8, edPub[:31]), "key"},
			{"okp wrong alg", coseOKP(-7, edPub), "alg"},
			{"okp missing alg", cbor(map[int64]any{1: int64(1), -1: int64(6), -2: edPub}), "alg"},
			{"ec2 off curve", coseEC2(1, -7, x256, yOff), "key"},
			{"ec2 zero point", coseEC2(1, -7, make([]byte, 32), make([]byte, 32)), "key"},
			{"ec2 p256 short y", coseEC2(1, -7, x256, y256[:31]), "key"},
			{"ec2 p256 long x", coseEC2(1, -7, append([]byte{0}, x256...), y256), "key"},
			{"ec2 p384 with p256 alg", coseEC2(2, -7, x384, y384), "alg"},
			{"ec2 p256 with p384 alg", coseEC2(1, -35, x256, y256), "alg"},
			{"ec2 p521 with p384 alg", coseEC2(3, -35, x521, y521), "alg"},
			{"ec2 unknown curve", coseEC2(8, -8, x256, y256), "key"},
			{"ec2 x not bytes", cbor(map[int64]any{1: int64(2), 3: int64(-7), -1: int64(1), -2: "x", -3: y256}), "key"},
			{"rsa 2047 bits", coseRSA(-257, bigBytes(2047, true), e), "key"},
			{"rsa 2047 bits padded", coseRSA(-257, pad(bigBytes(2047, true), 256), e), "key"},
			{"rsa 8193 bits", coseRSA(-257, bigBytes(8193, true), e), "key"},
			{"rsa even exponent", coseRSA(-257, n2048, []byte{0x01, 0x00, 0x00}), "key"},
			{"rsa exponent one", coseRSA(-257, n2048, []byte{1}), "key"},
			{"rsa exponent zero", coseRSA(-257, n2048, []byte{0}), "key"},
			{"rsa exponent empty", coseRSA(-257, n2048, nil), "key"},
			{"rsa exponent huge", coseRSA(-257, n2048, binary.BigEndian.AppendUint64(nil, 1<<40+1)), "key"},
			{"rsa wrong alg", coseRSA(-7, n2048, e), "alg"},
			{"rsa es256 alg", coseRSA(-8, n2048, e), "alg"},
			{"too large", bigKey, "too_large"},
			{"trailing bytes", append(coseOKP(-8, edPub), 0x00), "parse"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := webauthn.ParseCOSEKey(tc.raw)
				if err == nil {
					t.Fatal("accepted")
				}
				if r := webauthn.Reason(err); r != tc.reason {
					t.Fatalf("reason %q want %q (%v)", r, tc.reason, err)
				}
			})
		}
	})
	t.Run("reason of foreign error", func(t *testing.T) {
		if webauthn.Reason(nil) != "" {
			t.Fatal("nil error has a reason")
		}
		if webauthn.Reason(errForeign) != "parse" {
			t.Fatal("foreign error reason not bounded")
		}
	})
}

type foreignError struct{}

func (foreignError) Error() string { return "foreign" }

var errForeign error = foreignError{}

func FuzzParseCOSEKey(f *testing.F) {
	_, edPub := genEd(f)
	_, x, y := genEC(f, elliptic.P256())
	f.Add(coseOKP(-8, edPub))
	f.Add(coseEC2(1, -7, x, y))
	f.Add(coseRSA(-257, bigBytes(2048, true), []byte{1, 0, 1}))
	f.Add(coseRSA(-37, bigBytes(8192, true), []byte{3}))
	f.Add([]byte{0xa0})
	f.Add([]byte{0xa1, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, raw []byte) {
		pk, err := webauthn.ParseCOSEKey(raw)
		if err != nil {
			switch webauthn.Reason(err) {
			case "parse", "key", "alg", "too_large":
			default:
				t.Fatalf("reason %q", webauthn.Reason(err))
			}
			return
		}
		if pk.Key == nil {
			t.Fatal("nil key without error")
		}
		switch pk.Alg {
		case -8, -7, -35, -36, -257, -37:
		default:
			t.Fatalf("alg %d accepted", pk.Alg)
		}
	})
}
