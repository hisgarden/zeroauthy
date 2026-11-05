package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// authDataSeed builds authenticator data with attested credential data and an
// extension map, the richest shape parseAuthData accepts.
func authDataSeed(flags byte, idLen int, cose, ext []byte) []byte {
	h := sha256.Sum256([]byte("example.test"))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, 7)
	if flags&flagAT != 0 {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(idLen))
		out = append(out, bytes.Repeat([]byte{1}, idLen)...)
		out = append(out, cose...)
	}
	if flags&flagED != 0 {
		out = append(out, ext...)
	}
	return out
}

func FuzzParseAuthData(f *testing.F) {
	cose := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20}
	cose = append(cose, make([]byte, 32)...)
	f.Add(authDataSeed(flagUP, 0, nil, nil))
	f.Add(authDataSeed(flagUP|flagUV|flagAT, 32, cose, nil))
	f.Add(authDataSeed(flagUP|flagAT|flagED, 16, cose, []byte{0xa1, 0x61, 'x', 0xf5}))
	f.Add(authDataSeed(flagUP|flagED, 0, nil, []byte{0xa0}))
	f.Add(authDataSeed(flagUP|flagAT, 1023, cose, nil))
	f.Add(make([]byte, 36))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, in []byte) {
		ad, err := parseAuthData(in)
		if err != nil {
			switch Reason(err) {
			case ReasonParse, ReasonTooLarge:
			default:
				t.Fatalf("reason %q", Reason(err))
			}
			return
		}
		if ad == nil || len(in) < 37 {
			t.Fatalf("accepted %d bytes", len(in))
		}
		if !bytes.Equal(ad.RPIDHash[:], in[:32]) || ad.Flags != in[32] {
			t.Fatal("header mismatch")
		}
		if (ad.Attested != nil) != (ad.Flags&flagAT != 0) {
			t.Fatal("attested data disagrees with AT flag")
		}
		if ad.Attested != nil {
			if n := len(ad.Attested.ID); n == 0 || n > CredentialIDMax {
				t.Fatalf("credential id length %d", n)
			}
			if n := len(ad.Attested.COSE); n == 0 || n > COSEMax {
				t.Fatalf("cose length %d", n)
			}
		}
		if (ad.Extensions != nil) != (ad.Flags&flagED != 0) {
			t.Fatal("extensions disagree with ED flag")
		}
	})
}
