package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math"
	"math/big"
)

// COSE algorithm identifiers (RFC 9053, RFC 8812) this package verifies.
const (
	AlgEdDSA = -8   // Ed25519
	AlgES256 = -7   // ECDSA P-256 with SHA-256
	AlgES384 = -35  // ECDSA P-384 with SHA-384
	AlgES512 = -36  // ECDSA P-521 with SHA-512
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256
	AlgPS256 = -37  // RSASSA-PSS with SHA-256
)

// RegistrationAlgs are the algorithms offered at registration, in the
// documented order (§4.5). Assertions also accept ES384, ES512 and PS256 keys
// imported through the Management API (LR33b-11).
var RegistrationAlgs = []int64{AlgEdDSA, AlgES256, AlgRS256}

// PublicKey is a parsed COSE_Key: its algorithm and the standard-library
// key, one of ed25519.PublicKey, *ecdsa.PublicKey or *rsa.PublicKey.
type PublicKey struct {
	Alg int64
	Key crypto.PublicKey
}

// COSE_Key labels (RFC 9052 §7, RFC 9053 §7).
const (
	coseKty = 1
	coseAlg = 3
	coseCrv = -1 // OKP and EC2: curve; RSA: n
	coseX   = -2 // OKP and EC2: x; RSA: e
	coseY   = -3 // EC2: y; RSA: d (private)

	ktyOKP = 1
	ktyEC2 = 2
	ktyRSA = 3

	crvP256    = 1
	crvP384    = 2
	crvP521    = 3
	crvEd25519 = 6
)

// ParseCOSEKey parses one public COSE_Key of at most COSEMax bytes (§4.2):
// OKP Ed25519 (-8); EC2 P-256 (-7), P-384 (-35) and P-521 (-36) with the
// point checked on the curve; RSA (-257, -37) with a 2048–8192-bit modulus
// and an odd public exponent above one. Any label outside the public set
// for the key type, private material included, is refused. Reasons:
// too_large, parse (CBOR), key (shape or value) and alg (algorithm does not
// match the key type or curve).
func ParseCOSEKey(raw []byte) (PublicKey, error) {
	if len(raw) > COSEMax {
		return PublicKey{}, fail(ReasonTooLarge, "cose key too large")
	}
	if len(raw) == 0 {
		return PublicKey{}, fail(ReasonParse, "empty cose key")
	}
	v, err := DecodeCBOR(raw, CBORDepth, CBORItems)
	if err != nil {
		return PublicKey{}, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return PublicKey{}, fail(ReasonKey, "cose key is not a map")
	}
	integer := func(label int64) (int64, bool) {
		n, ok := m[label].(int64)
		return n, ok
	}
	bytes := func(label int64) ([]byte, bool) {
		b, ok := m[label].([]byte)
		return b, ok
	}
	kty, ok := integer(coseKty)
	if !ok {
		return PublicKey{}, fail(ReasonKey, "cose key type missing")
	}
	allowed := map[int64]bool{coseKty: true, coseAlg: true, coseCrv: true, coseX: true}
	if kty == ktyEC2 {
		allowed[coseY] = true
	}
	for label := range m {
		n, ok := label.(int64)
		if !ok || !allowed[n] {
			return PublicKey{}, fail(ReasonKey, "cose key label not allowed")
		}
	}
	alg, hasAlg := integer(coseAlg)
	switch kty {
	case ktyOKP:
		crv, ok := integer(coseCrv)
		if !ok || crv != crvEd25519 {
			return PublicKey{}, fail(ReasonKey, "okp curve not supported")
		}
		x, ok := bytes(coseX)
		if !ok || len(x) != ed25519.PublicKeySize {
			return PublicKey{}, fail(ReasonKey, "okp public key length")
		}
		if !hasAlg || alg != AlgEdDSA {
			return PublicKey{}, fail(ReasonAlg, "okp algorithm must be eddsa")
		}
		key := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(key, x)
		return PublicKey{Alg: alg, Key: key}, nil
	case ktyEC2:
		crv, ok := integer(coseCrv)
		if !ok {
			return PublicKey{}, fail(ReasonKey, "ec2 curve missing")
		}
		var curve elliptic.Curve
		var want int64
		switch crv {
		case crvP256:
			curve, want = elliptic.P256(), AlgES256
		case crvP384:
			curve, want = elliptic.P384(), AlgES384
		case crvP521:
			curve, want = elliptic.P521(), AlgES512
		default:
			return PublicKey{}, fail(ReasonKey, "ec2 curve not supported")
		}
		size := (curve.Params().BitSize + 7) / 8
		x, okX := bytes(coseX)
		y, okY := bytes(coseY)
		if !okX || !okY || len(x) != size || len(y) != size {
			return PublicKey{}, fail(ReasonKey, "ec2 coordinate length")
		}
		if !hasAlg || alg != want {
			return PublicKey{}, fail(ReasonAlg, "ec2 algorithm does not match curve")
		}
		point := make([]byte, 0, 1+2*size)
		point = append(point, 0x04)
		point = append(point, x...)
		point = append(point, y...)
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return PublicKey{}, fail(ReasonKey, "ec2 point not on curve")
		}
		return PublicKey{Alg: alg, Key: key}, nil
	case ktyRSA:
		nBytes, okN := bytes(coseCrv)
		eBytes, okE := bytes(coseX)
		if !okN || !okE || len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
			return PublicKey{}, fail(ReasonKey, "rsa parameters")
		}
		n := new(big.Int).SetBytes(nBytes)
		if bits := n.BitLen(); bits < 2048 || bits > 8192 {
			return PublicKey{}, fail(ReasonKey, "rsa modulus size")
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() > math.MaxInt32 || e.Int64() <= 1 || e.Bit(0) == 0 {
			return PublicKey{}, fail(ReasonKey, "rsa public exponent")
		}
		if !hasAlg || (alg != AlgRS256 && alg != AlgPS256) {
			return PublicKey{}, fail(ReasonAlg, "rsa algorithm not supported")
		}
		return PublicKey{Alg: alg, Key: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
	}
	return PublicKey{}, fail(ReasonKey, "cose key type not supported")
}
