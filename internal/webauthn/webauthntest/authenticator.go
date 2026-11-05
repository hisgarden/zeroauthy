// Package webauthntest is an in-tree software authenticator for tests. It
// produces PublicKeyCredential JSON for registrations and assertions with
// knobs for every value the verifier checks, so tests can exercise each
// refusal without a browser.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

// Options are the authenticator's knobs. The zero value is a plain P-256
// (-7) authenticator with attestation format "none", UP set, no UV, not
// backup eligible, sign count 0 and no attachment reported (a Level 2
// shape). Knobs may be changed between calls through Authenticator.Options.
type Options struct {
	Alg            int64  // COSE algorithm: -8, -7, -35, -36, -257, -37; 0 means -7
	UV, BE, BS     bool   // flags
	Attachment     string // "", "platform" or "cross-platform"; "" omits the member
	Format         string // attestation format; "" means "none"
	SignCount      uint32 // reported in every response
	OmitUserHandle bool   // assertions carry userHandle null
	CrossOrigin    bool   // clientData crossOrigin: true
	TopOrigin      string // clientData topOrigin when set
	TamperRPIDHash bool   // flip a bit of the RP ID hash

	// Shapes beyond the plan's list, for the parser tests.
	NoUP              bool           // clear the UP flag
	RFUFlags          byte           // OR-ed into the flags (bits 1 and 5 are reserved)
	CredentialID      []byte         // nil means 32 random bytes
	AAGUID            [16]byte       // registration AAGUID
	Transports        []string       // response.transports; nil omits the member
	AuthDataTail      []byte         // appended after the authenticator data
	Extensions        map[string]any // sets ED and appends this CBOR map
	AttStmt           map[string]any // attestation statement; nil picks one for the format
	ClientDataType    string         // overrides clientData type
	ClientDataPadding int            // bytes of padding added to clientDataJSON
}

// Authenticator holds one credential. Options may be changed between calls.
type Authenticator struct {
	Options
	alg        int64
	private    crypto.Signer
	cose       []byte
	credential []byte
	userHandle []byte
}

// New generates a key for opts.Alg and a credential ID.
func New(opts Options) *Authenticator {
	a := &Authenticator{Options: opts, alg: opts.Alg}
	if a.alg == 0 {
		a.alg = webauthn.AlgES256
	}
	var err error
	switch a.alg {
	case webauthn.AlgEdDSA:
		var pub ed25519.PublicKey
		var priv ed25519.PrivateKey
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		a.private = priv
		a.cose = encodeCBOR(map[int64]any{1: int64(1), 3: a.alg, -1: int64(6), -2: []byte(pub)})
	case webauthn.AlgES256, webauthn.AlgES384, webauthn.AlgES512:
		curves := map[int64]struct {
			curve elliptic.Curve
			crv   int64
		}{webauthn.AlgES256: {elliptic.P256(), 1}, webauthn.AlgES384: {elliptic.P384(), 2}, webauthn.AlgES512: {elliptic.P521(), 3}}
		c := curves[a.alg]
		var key *ecdsa.PrivateKey
		key, err = ecdsa.GenerateKey(c.curve, rand.Reader)
		if err == nil {
			size := (c.curve.Params().BitSize + 7) / 8
			a.private = key
			a.cose = encodeCBOR(map[int64]any{1: int64(2), 3: a.alg, -1: c.crv, -2: leftPad(key.X.Bytes(), size), -3: leftPad(key.Y.Bytes(), size)})
		}
	case webauthn.AlgRS256, webauthn.AlgPS256:
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			a.private = key
			a.cose = encodeCBOR(map[int64]any{1: int64(3), 3: a.alg, -1: key.N.Bytes(), -2: big3(key.E)})
		}
	default:
		panic("webauthntest: algorithm not supported")
	}
	if err != nil {
		panic(err)
	}
	a.credential = opts.CredentialID
	if a.credential == nil {
		a.credential = make([]byte, 32)
		if _, err := rand.Read(a.credential); err != nil {
			panic(err)
		}
	}
	return a
}

// CredentialID returns the credential ID this authenticator reports.
func (a *Authenticator) CredentialID() []byte { return append([]byte(nil), a.credential...) }

// PublicKeyCOSE returns the COSE_Key of the credential's public key.
func (a *Authenticator) PublicKeyCOSE() []byte { return append([]byte(nil), a.cose...) }

// UserHandle returns the user handle given at Create, or nil before it.
func (a *Authenticator) UserHandle() []byte { return append([]byte(nil), a.userHandle...) }

// Create answers navigator.credentials.create for opts at origin with a
// PublicKeyCredential JSON document (attestation response).
func (a *Authenticator) Create(opts webauthn.CreationOptions, origin string) []byte {
	a.userHandle = append([]byte(nil), opts.UserID...)
	clientData := a.clientData("webauthn.create", opts.Challenge, origin)
	authData := a.authData(opts.RPID, true)
	format := a.Format
	if format == "" {
		format = "none"
	}
	var stmt any = map[string]any{}
	if a.AttStmt != nil {
		stmt = a.AttStmt
	} else if format != "none" {
		stmt = map[string]any{"alg": a.alg, "sig": []byte{1, 2, 3}}
	}
	attestation := encodeCBOR(map[string]any{"fmt": format, "attStmt": stmt, "authData": authData})
	response := map[string]any{"clientDataJSON": b64(clientData), "attestationObject": b64(attestation)}
	if a.Transports != nil {
		response["transports"] = a.Transports
	}
	return a.credentialJSON(response)
}

// Get answers navigator.credentials.get for opts at origin with a
// PublicKeyCredential JSON document (assertion response).
func (a *Authenticator) Get(opts webauthn.RequestOptions, origin string) []byte {
	clientData := a.clientData("webauthn.get", opts.Challenge, origin)
	authData := a.authData(opts.RPID, false)
	hash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), hash[:]...)
	response := map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(a.sign(signed))}
	if a.OmitUserHandle {
		response["userHandle"] = nil
	} else {
		response["userHandle"] = b64(a.userHandle)
	}
	return a.credentialJSON(response)
}

func (a *Authenticator) credentialJSON(response map[string]any) []byte {
	doc := map[string]any{"id": b64(a.credential), "rawId": b64(a.credential), "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}}
	if a.Attachment != "" {
		doc["authenticatorAttachment"] = a.Attachment
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

func (a *Authenticator) clientData(kind string, challenge []byte, origin string) []byte {
	if a.ClientDataType != "" {
		kind = a.ClientDataType
	}
	doc := map[string]any{"type": kind, "challenge": b64(challenge), "origin": origin}
	if a.CrossOrigin {
		doc["crossOrigin"] = true
	}
	if a.TopOrigin != "" {
		doc["topOrigin"] = a.TopOrigin
	}
	if a.ClientDataPadding > 0 {
		pad := make([]byte, a.ClientDataPadding)
		for i := range pad {
			pad[i] = 'x'
		}
		doc["pad"] = string(pad)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

func (a *Authenticator) authData(rpID string, attested bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	if a.TamperRPIDHash {
		hash[0] ^= 0x80
	}
	flags := a.RFUFlags
	if !a.NoUP {
		flags |= 1 << 0
	}
	if a.UV {
		flags |= 1 << 2
	}
	if a.BE {
		flags |= 1 << 3
	}
	if a.BS {
		flags |= 1 << 4
	}
	if attested {
		flags |= 1 << 6
	}
	if a.Extensions != nil {
		flags |= 1 << 7
	}
	out := append([]byte(nil), hash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.SignCount)
	if attested {
		out = append(out, a.AAGUID[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credential)))
		out = append(out, a.credential...)
		out = append(out, a.cose...)
	}
	if a.Extensions != nil {
		out = append(out, encodeCBOR(a.Extensions)...)
	}
	return append(out, a.AuthDataTail...)
}

func (a *Authenticator) sign(msg []byte) []byte {
	var sig []byte
	var err error
	switch key := a.private.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(key, msg)
	case *ecdsa.PrivateKey:
		var digest []byte
		switch a.alg {
		case webauthn.AlgES256:
			h := sha256.Sum256(msg)
			digest = h[:]
		case webauthn.AlgES384:
			h := sha512.Sum384(msg)
			digest = h[:]
		default:
			h := sha512.Sum512(msg)
			digest = h[:]
		}
		sig, err = ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		h := sha256.Sum256(msg)
		if a.alg == webauthn.AlgPS256 {
			sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		}
	}
	if err != nil {
		panic(err)
	}
	return sig
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func leftPad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func big3(e int) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(e))
	for len(out) > 1 && out[0] == 0 {
		out = out[1:]
	}
	return out
}

// encodeCBOR encodes the value shapes the authenticator needs: int64,
// []byte, string, bool, nil, []any, []string, map[string]any and
// map[int64]any, with map keys sorted.
func encodeCBOR(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0xf6}
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case int:
		return encodeCBOR(int64(x))
	case int64:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []string:
		out := cborHead(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, encodeCBOR(e)...)
		}
		return out
	case []any:
		out := cborHead(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, encodeCBOR(e)...)
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
			out = append(out, encodeCBOR(k)...)
			out = append(out, encodeCBOR(x[k])...)
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
			out = append(out, encodeCBOR(k)...)
			out = append(out, encodeCBOR(x[k])...)
		}
		return out
	}
	panic("webauthntest: value not encodable")
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
