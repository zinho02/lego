package registration

import (
	"crypto/pqc"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/acme"
	"github.com/zinho02/lego/v4/acme/api"
	"github.com/zinho02/lego/v4/platform/tester"
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

func TestRegistrar_ResolveAccountByKey(t *testing.T) {
	mux, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", apiURL+"/account")
		err := tester.WriteJSONResponse(w, acme.Account{
			Status: "valid",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	key, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Could not generate test key")

	user := mockUser{
		email:      "test@test.com",
		regres:     &Resource{},
		privatekey: key,
	}

	core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", key)
	require.NoError(t, err)

	registrar := NewRegistrar(core, user)

	res, err := registrar.ResolveAccountByKey()
	require.NoError(t, err, "Unexpected error resolving account by key")

	assert.Equal(t, "valid", res.Body.Status, "Unexpected account status")
}

func BenchmarkRegistrar_ResolveAccountByKey(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				mux, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Location", apiURL+"/account")
					err := tester.WriteJSONResponse(w, acme.Account{
						Status: "valid",
					})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				})

				key, err := pqc.GenerateKey(v.input)
				require.NoError(b, err, "Could not generate test key")

				user := mockUser{
					email:      "test@test.com",
					regres:     &Resource{},
					privatekey: key,
				}

				core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", key)
				require.NoError(b, err)

				registrar := NewRegistrar(core, user)

				res, err := registrar.ResolveAccountByKey()
				require.NoError(b, err, "Unexpected error resolving account by key")

				assert.Equal(b, "valid", res.Body.Status, "Unexpected account status")
			}
		})
	}
}
