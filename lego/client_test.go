package lego

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/platform/tester"
	"github.com/zinho02/lego/v4/registration"
)

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
	for n := 0; n < b.N; n++ {
		_, apiURL, tearDown := tester.SetupFakeAPI()
		defer tearDown()

		keyBits := 32 // small value keeps test fast
		key, err := rsa.GenerateKey(rand.Reader, keyBits)
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
}

type mockUser struct {
	email      string
	regres     *registration.Resource
	privatekey *rsa.PrivateKey
}

func (u mockUser) GetEmail() string                        { return u.email }
func (u mockUser) GetRegistration() *registration.Resource { return u.regres }
func (u mockUser) GetPrivateKey() crypto.PrivateKey        { return u.privatekey }
