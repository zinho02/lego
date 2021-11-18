package lego

import (
	"crypto"
	"crypto/pqc"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/platform/tester"
	"github.com/zinho02/lego/v4/registration"
)

var table = []struct {
	input string
}{
	{input: "dilithium5"},
	{input: "dilithium5-aes"},
	{input: "falcon-1024"},
	{input: "rainbow-V-classic"},
	{input: "rainbow-V-circumzenithal"},
	{input: "rainbow-V-compressed"},
	{input: "sphincs+-haraka-256s-simple"},
	{input: "sphincs+-haraka-256f-simple"},
	{input: "sphincs+-haraka-256s-robust"},
	{input: "sphincs+-haraka-256f-robust"},
	{input: "sphincs+-sha256-256s-simple"},
	{input: "sphincs+-sha256-256f-simple"},
	{input: "sphincs+-sha256-256s-robust"},
	{input: "sphincs+-sha256-256f-robust"},
	{input: "sphincs+-shake256-256s-simple"},
	{input: "sphincs+-shake256-256f-simple"},
	{input: "sphincs+-shake256-256s-robust"},
	{input: "sphincs+-shake256-256f-robust"},
	{input: "dilithium2"},
	{input: "dilithium2-aes"},
	{input: "falcon-512"},
	{input: "rainbow-I-classic"},
	{input: "rainbow-I-circumzenithal"},
	{input: "rainbow-I-compressed"},
	{input: "sphincs+-haraka-128s-simple"},
	{input: "sphincs+-haraka-128f-simple"},
	{input: "sphincs+-haraka-128s-robust"},
	{input: "sphincs+-haraka-128f-robust"},
	{input: "sphincs+-sha256-128s-simple"},
	{input: "sphincs+-sha256-128f-simple"},
	{input: "sphincs+-sha256-128s-robust"},
	{input: "sphincs+-sha256-128f-robust"},
	{input: "sphincs+-shake256-128s-simple"},
	{input: "sphincs+-shake256-128f-simple"},
	{input: "sphincs+-shake256-128s-robust"},
	{input: "sphincs+-shake256-128f-robust"},
}

func TestNewClient(t *testing.T) {
	_, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	keyBits := 32 // small value keeps test fast
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     new(registration.Resource),
		privatekey: key,
	}

	config := NewConfig(user)
	config.CADirURL = apiURL + "/dir"

	client, err := NewClient(config)
	require.NoError(t, err, "Could not create client")

	assert.NotNil(t, client)
}

func BenchmarkNewClient(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				keyBits := 32 // small value keeps test fast
				key, err := pqc.GenerateKey(v.input)
				require.NoError(b, err, "Could not generate test key")

				user := mockUser{
					email:      "test@test.com",
					regres:     new(registration.Resource),
					privatekey: key,
				}

				config := NewConfig(user)
				config.CADirURL = apiURL + "/dir"

				client, err := NewClient(config)
				require.NoError(b, err, "Could not create client")

				assert.NotNil(b, client)
			}
		})
	}
}

type mockUser struct {
	email      string
	regres     *registration.Resource
	privatekey *rsa.PrivateKey
}

func (u mockUser) GetEmail() string                        { return u.email }
func (u mockUser) GetRegistration() *registration.Resource { return u.regres }
func (u mockUser) GetPrivateKey() crypto.PrivateKey        { return u.privatekey }
