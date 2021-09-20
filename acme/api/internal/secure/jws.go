package secure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pqc"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/zinho02/lego/v4/acme/api/internal/nonces"
	jose "gopkg.in/square/go-jose.v2"
)

// JWS Represents a JWS.
type JWS struct {
	privKey crypto.PrivateKey
	kid     string // Key identifier
	nonces  *nonces.Manager
}

// NewJWS Create a new JWS.
func NewJWS(privateKey crypto.PrivateKey, kid string, nonceManager *nonces.Manager) *JWS {
	return &JWS{
		privKey: privateKey,
		nonces:  nonceManager,
		kid:     kid,
	}
}

// SetKid Sets a key identifier.
func (j *JWS) SetKid(kid string) {
	j.kid = kid
}

// SignContent Signs a content with the JWS.
func (j *JWS) SignContent(url string, content []byte) (*jose.JSONWebSignature, error) {
	var alg jose.SignatureAlgorithm
	switch k := j.privKey.(type) {
	case pqc.PrivateKey:
		switch k.AlgName {
		case "dilithium5":
			alg = jose.Dilithium5
		case "dilithium5-aes":
			alg = jose.Dilithium5AES
		case "rainbow-v-classic":
			alg = jose.RainbowVClassic
		case "rainbow-v-circumzenithal":
			alg = jose.RainbowVCircumzenithal
		case "rainbow-v-compressed":
			alg = jose.RainbowVCompressed
		case "sphincs+-haraka-256s-simple":
			alg = jose.SphincsPlusHaraka256sSimple
		case "sphincs+-haraka-256f-simple":
			alg = jose.SphincsPlusHaraka256fSimple
		case "sphincs+-haraka-256s-robust":
			alg = jose.SphincsPlusHaraka256sRobust
		case "sphincs+-haraka-256f-robust":
			alg = jose.SphincsPlusHaraka256fRobust
		case "sphincs+-sha256-256s-simple":
			alg = jose.SphincsPlusSHA256256sSimple
		case "sphincs+-sha256-256f-simple":
			alg = jose.SphincsPlusSHA256256fSimple
		case "sphincs+-sha256-256s-robust":
			alg = jose.SphincsPlusSHA256256sRobust
		case "sphincs+-sha256-256f-robust":
			alg = jose.SphincsPlusSHA256256fRobust
		case "sphincs+-shake256-256s-simple":
			alg = jose.SphincsPlusSHAKE256256sSimple
		case "sphincs+-shake256-256f-simple":
			alg = jose.SphincsPlusSHAKE256256fSimple
		case "sphincs+-shake256-256s-robust":
			alg = jose.SphincsPlusSHAKE256256sRobust
		case "sphincs+-shake256-256f-robust":
			alg = jose.SphincsPlusSHAKE256256fRobust
		case "dilithium2":
			alg = jose.Dilithium2
		case "dilithium2-aes":
			alg = jose.Dilithium2AES
		case "rainbow-i-classic":
			alg = jose.RainbowIClassic
		case "rainbow-i-circumzenithal":
			alg = jose.RainbowICircumzenithal
		case "rainbow-i-compressed":
			alg = jose.RainbowICompressed
		case "sphincs+-haraka-128s-simple":
			alg = jose.SphincsPlusHaraka128sSimple
		case "sphincs+-haraka-128f-simple":
			alg = jose.SphincsPlusHaraka128fSimple
		case "sphincs+-haraka-128s-robust":
			alg = jose.SphincsPlusHaraka128sRobust
		case "sphincs+-haraka-128f-robust":
			alg = jose.SphincsPlusHaraka128fRobust
		case "sphincs+-sha256-128s-simple":
			alg = jose.SphincsPlusSHA256128sSimple
		case "sphincs+-sha256-128f-simple":
			alg = jose.SphincsPlusSHA256128fSimple
		case "sphincs+-sha256-128s-robust":
			alg = jose.SphincsPlusSHA256128sRobust
		case "sphincs+-sha256-128f-robust":
			alg = jose.SphincsPlusSHA256128fRobust
		case "sphincs+-shake256-128s-simple":
			alg = jose.SphincsPlusSHAKE256128sSimple
		case "sphincs+-shake256-128f-simple":
			alg = jose.SphincsPlusSHAKE256128fSimple
		case "sphincs+-shake256-128s-robust":
			alg = jose.SphincsPlusSHAKE256128sRobust
		case "sphincs+-shake256-128f-robust":
			alg = jose.SphincsPlusSHAKE256128fRobust
		}
	case *pqc.PrivateKey:
		switch k.AlgName {
		case "dilithium5":
			alg = jose.Dilithium5
		case "dilithium5-aes":
			alg = jose.Dilithium5AES
		case "rainbow-v-classic":
			alg = jose.RainbowVClassic
		case "rainbow-v-circumzenithal":
			alg = jose.RainbowVCircumzenithal
		case "rainbow-v-compressed":
			alg = jose.RainbowVCompressed
		case "sphincs+-haraka-256s-simple":
			alg = jose.SphincsPlusHaraka256sSimple
		case "sphincs+-haraka-256f-simple":
			alg = jose.SphincsPlusHaraka256fSimple
		case "sphincs+-haraka-256s-robust":
			alg = jose.SphincsPlusHaraka256sRobust
		case "sphincs+-haraka-256f-robust":
			alg = jose.SphincsPlusHaraka256fRobust
		case "sphincs+-sha256-256s-simple":
			alg = jose.SphincsPlusSHA256256sSimple
		case "sphincs+-sha256-256f-simple":
			alg = jose.SphincsPlusSHA256256fSimple
		case "sphincs+-sha256-256s-robust":
			alg = jose.SphincsPlusSHA256256sRobust
		case "sphincs+-sha256-256f-robust":
			alg = jose.SphincsPlusSHA256256fRobust
		case "sphincs+-shake256-256s-simple":
			alg = jose.SphincsPlusSHAKE256256sSimple
		case "sphincs+-shake256-256f-simple":
			alg = jose.SphincsPlusSHAKE256256fSimple
		case "sphincs+-shake256-256s-robust":
			alg = jose.SphincsPlusSHAKE256256sRobust
		case "sphincs+-shake256-256f-robust":
			alg = jose.SphincsPlusSHAKE256256fRobust
		case "dilithium2":
			alg = jose.Dilithium2
		case "dilithium2-aes":
			alg = jose.Dilithium2AES
		case "rainbow-i-classic":
			alg = jose.RainbowIClassic
		case "rainbow-i-circumzenithal":
			alg = jose.RainbowICircumzenithal
		case "rainbow-i-compressed":
			alg = jose.RainbowICompressed
		case "sphincs+-haraka-128s-simple":
			alg = jose.SphincsPlusHaraka128sSimple
		case "sphincs+-haraka-128f-simple":
			alg = jose.SphincsPlusHaraka128fSimple
		case "sphincs+-haraka-128s-robust":
			alg = jose.SphincsPlusHaraka128sRobust
		case "sphincs+-haraka-128f-robust":
			alg = jose.SphincsPlusHaraka128fRobust
		case "sphincs+-sha256-128s-simple":
			alg = jose.SphincsPlusSHA256128sSimple
		case "sphincs+-sha256-128f-simple":
			alg = jose.SphincsPlusSHA256128fSimple
		case "sphincs+-sha256-128s-robust":
			alg = jose.SphincsPlusSHA256128sRobust
		case "sphincs+-sha256-128f-robust":
			alg = jose.SphincsPlusSHA256128fRobust
		case "sphincs+-shake256-128s-simple":
			alg = jose.SphincsPlusSHAKE256128sSimple
		case "sphincs+-shake256-128f-simple":
			alg = jose.SphincsPlusSHAKE256128fSimple
		case "sphincs+-shake256-128s-robust":
			alg = jose.SphincsPlusSHAKE256128sRobust
		case "sphincs+-shake256-128f-robust":
			alg = jose.SphincsPlusSHAKE256128fRobust
		}
	case *rsa.PrivateKey:
		alg = jose.RS256
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			alg = jose.ES256
		} else if k.Curve == elliptic.P384() {
			alg = jose.ES384
		}
	}

	signKey := jose.SigningKey{
		Algorithm: alg,
		Key:       jose.JSONWebKey{Key: j.privKey, KeyID: j.kid},
	}

	options := jose.SignerOptions{
		NonceSource: j.nonces,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if j.kid == "" {
		options.EmbedJWK = true
	}

	signer, err := jose.NewSigner(signKey, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	signed, err := signer.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content: %w", err)
	}
	return signed, nil
}

// SignEABContent Signs an external account binding content with the JWS.
func (j *JWS) SignEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: j.privKey}
	jwkJSON, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("acme: error encoding eab jwk key: %w", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmac},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
				"url": url,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create External Account Binding jose signer: %w", err)
	}

	signed, err := signer.Sign(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to External Account Binding sign content: %w", err)
	}

	return signed, nil
}

// GetKeyAuthorization Gets the key authorization for a token.
func (j *JWS) GetKeyAuthorization(token string) (string, error) {
	var publicKey crypto.PublicKey
	switch k := j.privKey.(type) {
	case *pqc.PrivateKey:
		publicKey = k.Public()
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	}

	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: publicKey}

	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return token + "." + keyThumb, nil
}
