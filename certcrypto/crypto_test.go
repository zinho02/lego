package certcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pqc"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var table = []struct {
	input KeyType
	name  string
	bits  int
}{
	{input: RSA8192, name: "RSA8192", bits: 8192},
	{input: RSA2048, name: "RSA2048", bits: 2048},
	{input: EC384, name: "EC384", bits: 384},
	{input: EC256, name: "EC256", bits: 256},
}

// var table = []struct {
// 	input string
// }{
// 	{input: "dilithium5"},
// 	{input: "dilithium5-aes"},
// 	{input: "falcon-1024"},
// 	{input: "rainbow-V-classic"},
// 	{input: "rainbow-V-circumzenithal"},
// 	{input: "rainbow-V-compressed"},
// 	{input: "sphincs+-haraka-256s-simple"},
// 	{input: "sphincs+-haraka-256f-simple"},
// 	{input: "sphincs+-haraka-256s-robust"},
// 	{input: "sphincs+-haraka-256f-robust"},
// 	{input: "sphincs+-sha256-256s-simple"},
// 	{input: "sphincs+-sha256-256f-simple"},
// 	{input: "sphincs+-sha256-256s-robust"},
// 	{input: "sphincs+-sha256-256f-robust"},
// 	{input: "sphincs+-shake256-256s-simple"},
// 	{input: "sphincs+-shake256-256f-simple"},
// 	{input: "sphincs+-shake256-256s-robust"},
// 	{input: "sphincs+-shake256-256f-robust"},
// 	{input: "dilithium2"},
// 	{input: "dilithium2-aes"},
// 	{input: "falcon-512"},
// 	{input: "rainbow-I-classic"},
// 	{input: "rainbow-I-circumzenithal"},
// 	{input: "rainbow-I-compressed"},
// 	{input: "sphincs+-haraka-128s-simple"},
// 	{input: "sphincs+-haraka-128f-simple"},
// 	{input: "sphincs+-haraka-128s-robust"},
// 	{input: "sphincs+-haraka-128f-robust"},
// 	{input: "sphincs+-sha256-128s-simple"},
// 	{input: "sphincs+-sha256-128f-simple"},
// 	{input: "sphincs+-sha256-128s-robust"},
// 	{input: "sphincs+-sha256-128f-robust"},
// 	{input: "sphincs+-shake256-128s-simple"},
// 	{input: "sphincs+-shake256-128f-simple"},
// 	{input: "sphincs+-shake256-128s-robust"},
// 	{input: "sphincs+-shake256-128f-robust"},
// }

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	assert.NotNil(t, key)
}

func BenchmarkGeneratePrivateKey(b *testing.B) {
	for _, v := range table {
		b.Run(v.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				key, err := GeneratePrivateKey(v.input)
				require.NoError(b, err, "Error generating private key")

				assert.NotNil(b, key)
			}
		})
	}
}

func TestGenerateCSR(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Error generating private key")

	type expected struct {
		len   int
		error bool
	}

	testCases := []struct {
		desc       string
		privateKey crypto.PrivateKey
		domain     string
		san        []string
		mustStaple bool
		expected   expected
	}{
		{
			desc:       "without SAN",
			privateKey: privateKey,
			domain:     "lego.acme",
			mustStaple: true,
			expected:   expected{len: 245},
		},
		{
			desc:       "without SAN",
			privateKey: privateKey,
			domain:     "lego.acme",
			san:        []string{},
			mustStaple: true,
			expected:   expected{len: 245},
		},
		{
			desc:       "with SAN",
			privateKey: privateKey,
			domain:     "lego.acme",
			san:        []string{"a.lego.acme", "b.lego.acme", "c.lego.acme"},
			mustStaple: true,
			expected:   expected{len: 296},
		},
		{
			desc:       "no domain",
			privateKey: privateKey,
			domain:     "",
			mustStaple: true,
			expected:   expected{len: 225},
		},
		{
			desc:       "no domain with SAN",
			privateKey: privateKey,
			domain:     "",
			san:        []string{"a.lego.acme", "b.lego.acme", "c.lego.acme"},
			mustStaple: true,
			expected:   expected{len: 276},
		},
		{
			desc:       "private key nil",
			privateKey: nil,
			domain:     "fizz.buzz",
			mustStaple: true,
			expected:   expected{error: true},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			csr, err := GenerateCSR(test.privateKey, test.domain, test.san, test.mustStaple)

			if test.expected.error {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "Error generating CSR")

				assert.NotEmpty(t, csr)
				assert.Len(t, csr, test.expected.len)
			}
		})
	}
}

func BenchmarkGenerateCSR(b *testing.B) {
	for _, v := range table {
		b.Run(v.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				privateKey, err := GeneratePrivateKey(v.input)
				require.NoError(b, err, "Error generating private key")

				type expected struct {
					len   int
					error bool
				}

				testCases := []struct {
					desc       string
					privateKey crypto.PrivateKey
					domain     string
					san        []string
					mustStaple bool
					expected   expected
				}{
					{
						desc:       "without SAN",
						privateKey: privateKey,
						domain:     "lego.acme",
						mustStaple: true,
						expected:   expected{len: 245},
					},
					{
						desc:       "without SAN",
						privateKey: privateKey,
						domain:     "lego.acme",
						san:        []string{},
						mustStaple: true,
						expected:   expected{len: 245},
					},
					{
						desc:       "with SAN",
						privateKey: privateKey,
						domain:     "lego.acme",
						san:        []string{"a.lego.acme", "b.lego.acme", "c.lego.acme"},
						mustStaple: true,
						expected:   expected{len: 296},
					},
					{
						desc:       "no domain",
						privateKey: privateKey,
						domain:     "",
						mustStaple: true,
						expected:   expected{len: 225},
					},
					{
						desc:       "no domain with SAN",
						privateKey: privateKey,
						domain:     "",
						san:        []string{"a.lego.acme", "b.lego.acme", "c.lego.acme"},
						mustStaple: true,
						expected:   expected{len: 276},
					},
					{
						desc:       "private key nil",
						privateKey: nil,
						domain:     "fizz.buzz",
						mustStaple: true,
						expected:   expected{error: true},
					},
				}

				for _, test := range testCases {
					test := test
					b.Run(test.desc, func(b *testing.B) {
						csr, err := GenerateCSR(test.privateKey, test.domain, test.san, test.mustStaple)

						if test.expected.error {
							require.Error(b, err)
						} else {
							require.NoError(b, err, "Error generating CSR")

							assert.NotEmpty(b, csr)
						}
					})
				}
			}
		})
	}
}

func TestPEMEncode(t *testing.T) {
	buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

	reader := MockRandReader{b: buf}
	key, err := rsa.GenerateKey(reader, 32)
	require.NoError(t, err, "Error generating private key")

	data := PEMEncode(key)
	require.NotNil(t, data)
	assert.Len(t, data, 127)
}

func BenchmarkPEMEncode(b *testing.B) {
	for _, v := range table {
		b.Run(v.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				key, err := GeneratePrivateKey(v.input)
				require.NoError(b, err, "Error generating private key")

				data := PEMEncode(key)
				require.NotNil(b, data)
			}
		})
	}
}

func TestParsePEMCertificate(t *testing.T) {
	privateKey, err := GeneratePrivateKey(RSA2048)
	require.NoError(t, err, "Error generating private key")

	expiration := time.Now().Add(365).Round(time.Second)
	certBytes, err := generateDerCert(privateKey.(*pqc.PrivateKey), expiration, "test.com", nil)
	require.NoError(t, err, "Error generating cert")

	buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

	// Some random string should return an error.
	cert, err := ParsePEMCertificate(buf.Bytes())
	require.Errorf(t, err, "returned %v", cert)

	// A DER encoded certificate should return an error.
	_, err = ParsePEMCertificate(certBytes)
	require.Error(t, err, "Expected to return an error for DER certificates")

	// A PEM encoded certificate should work ok.
	pemCert := PEMEncode(DERCertificateBytes(certBytes))
	cert, err = ParsePEMCertificate(pemCert)
	require.NoError(t, err)

	assert.Equal(t, expiration.UTC(), cert.NotAfter)
}

func BenchmarkParsePEMCertificate(b *testing.B) {
	for _, v := range table {
		b.Run(v.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				if v.input == RSA8192 || v.input == RSA2048 {
					privateKey, err := rsa.GenerateKey(rand.Reader, v.bits)
					require.NoError(b, err, "Error generating private key")

					expiration := time.Now().Add(365).Round(time.Second)
					certBytes, err := generateDerCertRSA(privateKey, expiration, "test.com", nil)
					require.NoError(b, err, "Error generating cert")

					buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

					// Some random string should return an error.
					cert, err := ParsePEMCertificate(buf.Bytes())
					require.Errorf(b, err, "returned %v", cert)

					// A DER encoded certificate should return an error.
					_, err = ParsePEMCertificate(certBytes)
					require.Error(b, err, "Expected to return an error for DER certificates")

					// A PEM encoded certificate should work ok.
					pemCert := PEMEncode(DERCertificateBytes(certBytes))
					cert, err = ParsePEMCertificate(pemCert)
					require.NoError(b, err)

					assert.Equal(b, expiration.UTC(), cert.NotAfter)
				} else {
					var privateKey *ecdsa.PrivateKey
					var err error
					if v.input == EC384 {
						privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
						require.NoError(b, err, "Error generating private key")
					} else {
						privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						require.NoError(b, err, "Error generating private key")
					}

					expiration := time.Now().Add(365).Round(time.Second)
					certBytes, err := generateDerCertECDSA(privateKey, expiration, "test.com", nil)
					require.NoError(b, err, "Error generating cert")

					buf := bytes.NewBufferString("TestingRSAIsSoMuchFun")

					// Some random string should return an error.
					cert, err := ParsePEMCertificate(buf.Bytes())
					require.Errorf(b, err, "returned %v", cert)

					// A DER encoded certificate should return an error.
					_, err = ParsePEMCertificate(certBytes)
					require.Error(b, err, "Expected to return an error for DER certificates")

					// A PEM encoded certificate should work ok.
					pemCert := PEMEncode(DERCertificateBytes(certBytes))
					cert, err = ParsePEMCertificate(pemCert)
					require.NoError(b, err)

					assert.Equal(b, expiration.UTC(), cert.NotAfter)
				}
			}
		})
	}
}

type MockRandReader struct {
	b *bytes.Buffer
}

func (r MockRandReader) Read(p []byte) (int, error) {
	return r.b.Read(p)
}
