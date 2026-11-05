package webauthn

import "encoding/binary"

// Authenticator data flag bits (WebAuthn Level 3 §6.1).
const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified
	flagBE = 1 << 3 // backup eligible
	flagBS = 1 << 4 // backed up
	flagAT = 1 << 6 // attested credential data included
	flagED = 1 << 7 // extension data included
)

// authData is parsed authenticator data. Attested is set exactly when the AT
// flag is; Extensions is set exactly when the ED flag is (a decoded map,
// kept only so callers can see it was well-formed).
type authData struct {
	RPIDHash   [32]byte
	Flags      byte
	SignCount  uint32
	Attested   *attestedCredential
	Extensions any
}

type attestedCredential struct {
	AAGUID [16]byte
	ID     []byte
	COSE   []byte // the raw COSE_Key, exactly the bytes the authenticator sent
}

func (a *authData) up() bool { return a.Flags&flagUP != 0 }
func (a *authData) uv() bool { return a.Flags&flagUV != 0 }
func (a *authData) be() bool { return a.Flags&flagBE != 0 }
func (a *authData) bs() bool { return a.Flags&flagBS != 0 }

// parseAuthData parses authenticator data exactly: the 37-byte header, then
// attested credential data when AT is set (AAGUID, length, credential ID of
// 1–1023 bytes, one COSE_Key of at most COSEMax bytes), then extensions when
// ED is set (one CBOR map). Any unparsed tail is an error. Flag bits
// reserved for future use are ignored. Reasons: parse, too_large.
func parseAuthData(b []byte) (*authData, error) {
	if len(b) > AttestationMax {
		return nil, fail(ReasonTooLarge, "authenticator data too large")
	}
	if len(b) < 37 {
		return nil, fail(ReasonParse, "authenticator data too short")
	}
	ad := &authData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	copy(ad.RPIDHash[:], b[:32])
	rest := b[37:]
	if ad.Flags&flagAT != 0 {
		if len(rest) < 18 {
			return nil, fail(ReasonParse, "attested credential data too short")
		}
		at := &attestedCredential{}
		copy(at.AAGUID[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n > CredentialIDMax {
			return nil, fail(ReasonTooLarge, "credential id too long")
		}
		if n == 0 || n > len(rest) {
			return nil, fail(ReasonParse, "credential id length")
		}
		at.ID = make([]byte, n)
		copy(at.ID, rest[:n])
		rest = rest[n:]
		// The COSE key is delimited by its own CBOR structure; decode it once
		// here to find its end, bounded like every other item.
		keyStart := rest
		v, after, err := DecodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		if _, ok := v.(map[any]any); !ok {
			return nil, fail(ReasonParse, "credential public key is not a map")
		}
		keyLen := len(keyStart) - len(after)
		if keyLen > COSEMax {
			return nil, fail(ReasonTooLarge, "credential public key too large")
		}
		at.COSE = make([]byte, keyLen)
		copy(at.COSE, keyStart[:keyLen])
		rest = after
		ad.Attested = at
	}
	if ad.Flags&flagED != 0 {
		v, after, err := DecodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[any]any)
		if !ok {
			return nil, fail(ReasonParse, "extensions are not a map")
		}
		ad.Extensions = m
		rest = after
	}
	if len(rest) != 0 {
		return nil, fail(ReasonParse, "unparsed authenticator data")
	}
	return ad, nil
}
