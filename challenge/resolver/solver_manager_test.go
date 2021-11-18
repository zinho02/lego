package resolver

import (
	"crypto/pqc"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/acme"
	"github.com/zinho02/lego/v4/acme/api"
	"github.com/zinho02/lego/v4/platform/tester"
	jose "gopkg.in/square/go-jose.v2"
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

func TestByType(t *testing.T) {
	challenges := []acme.Challenge{
		{Type: "dns-01"}, {Type: "tlsalpn-01"}, {Type: "http-01"},
	}

	sort.Sort(byType(challenges))

	expected := []acme.Challenge{
		{Type: "tlsalpn-01"}, {Type: "http-01"}, {Type: "dns-01"},
	}

	assert.Equal(t, expected, challenges)
}

func BenchmarkByType(b *testing.B) {
	for n := 0; n < b.N; n++ {
		challenges := []acme.Challenge{
			{Type: "dns-01"}, {Type: "tlsalpn-01"}, {Type: "http-01"},
		}

		sort.Sort(byType(challenges))

		expected := []acme.Challenge{
			{Type: "tlsalpn-01"}, {Type: "http-01"}, {Type: "dns-01"},
		}

		assert.Equal(b, expected, challenges)
	}
}

func TestValidate(t *testing.T) {
	mux, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	var statuses []string

	privateKey, _ := pqc.GenerateKey("dilithium5")

	mux.HandleFunc("/chlg", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if err := validateNoBody(privateKey, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Link", "<"+apiURL+`/my-authz>; rel="up"`)

		st := statuses[0]
		statuses = statuses[1:]

		chlg := &acme.Challenge{Type: "http-01", Status: st, URL: "http://example.com/", Token: "token"}
		if st == acme.StatusInvalid {
			chlg.Error = &acme.ProblemDetails{}
		}

		err := tester.WriteJSONResponse(w, chlg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/my-authz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		st := statuses[0]
		statuses = statuses[1:]

		authorization := acme.Authorization{
			Status:     st,
			Challenges: []acme.Challenge{},
		}

		if st == acme.StatusInvalid {
			chlg := acme.Challenge{
				Status: acme.StatusInvalid,
				Error:  &acme.ProblemDetails{},
			}
			authorization.Challenges = append(authorization.Challenges, chlg)
		}

		err := tester.WriteJSONResponse(w, authorization)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{
			name:     "POST-unexpected",
			statuses: []string{"weird"},
			want:     "unexpected",
		},
		{
			name:     "POST-valid",
			statuses: []string{acme.StatusValid},
		},
		{
			name:     "POST-invalid",
			statuses: []string{acme.StatusInvalid},
			want:     "error",
		},
		{
			name:     "POST-pending-unexpected",
			statuses: []string{acme.StatusPending, "weird"},
			want:     "unexpected",
		},
		{
			name:     "POST-pending-valid",
			statuses: []string{acme.StatusPending, acme.StatusValid},
		},
		{
			name:     "POST-pending-invalid",
			statuses: []string{acme.StatusPending, acme.StatusInvalid},
			want:     "error",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			statuses = test.statuses

			err := validate(core, "example.com", acme.Challenge{Type: "http-01", Token: "token", URL: apiURL + "/chlg"})
			if test.want == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.want)
			}
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				mux, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				var statuses []string

				privateKey, _ := pqc.GenerateKey(v.input)

				mux.HandleFunc("/chlg", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
						return
					}

					if err := validateNoBody(privateKey, r); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}

					w.Header().Set("Link", "<"+apiURL+`/my-authz>; rel="up"`)

					st := statuses[0]
					statuses = statuses[1:]

					chlg := &acme.Challenge{Type: "http-01", Status: st, URL: "http://example.com/", Token: "token"}
					if st == acme.StatusInvalid {
						chlg.Error = &acme.ProblemDetails{}
					}

					err := tester.WriteJSONResponse(w, chlg)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				})

				mux.HandleFunc("/my-authz", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
						return
					}

					st := statuses[0]
					statuses = statuses[1:]

					authorization := acme.Authorization{
						Status:     st,
						Challenges: []acme.Challenge{},
					}

					if st == acme.StatusInvalid {
						chlg := acme.Challenge{
							Status: acme.StatusInvalid,
							Error:  &acme.ProblemDetails{},
						}
						authorization.Challenges = append(authorization.Challenges, chlg)
					}

					err := tester.WriteJSONResponse(w, authorization)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				})

				core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
				require.NoError(b, err)

				testCases := []struct {
					name     string
					statuses []string
					want     string
				}{
					{
						name:     "POST-unexpected",
						statuses: []string{"weird"},
						want:     "unexpected",
					},
					{
						name:     "POST-valid",
						statuses: []string{acme.StatusValid},
					},
					{
						name:     "POST-invalid",
						statuses: []string{acme.StatusInvalid},
						want:     "error",
					},
					{
						name:     "POST-pending-unexpected",
						statuses: []string{acme.StatusPending, "weird"},
						want:     "unexpected",
					},
					{
						name:     "POST-pending-valid",
						statuses: []string{acme.StatusPending, acme.StatusValid},
					},
					{
						name:     "POST-pending-invalid",
						statuses: []string{acme.StatusPending, acme.StatusInvalid},
						want:     "error",
					},
				}

				for _, test := range testCases {
					b.Run(test.name, func(b *testing.B) {
						statuses = test.statuses

						err := validate(core, "example.com", acme.Challenge{Type: "http-01", Token: "token", URL: apiURL + "/chlg"})
						if test.want == "" {
							require.NoError(b, err)
						} else {
							require.Error(b, err)
							assert.Contains(b, err.Error(), test.want)
						}
					})
				}
			}
		})
	}
}

// validateNoBody reads the http.Request POST body, parses the JWS and validates it to read the body.
// If there is an error doing this,
// or if the JWS body is not the empty JSON payload "{}" or a POST-as-GET payload "" an error is returned.
// We use this to verify challenge POSTs to the ts below do not send a JWS body.
func validateNoBody(privateKey *pqc.PrivateKey, r *http.Request) error {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	jws, err := jose.ParseSigned(string(reqBody))
	if err != nil {
		return err
	}

	body, err := jws.Verify(&jose.JSONWebKey{
		Key:       privateKey.Public(),
		Algorithm: "RSA",
	})
	if err != nil {
		return err
	}

	if bodyStr := string(body); bodyStr != "{}" && bodyStr != "" {
		return fmt.Errorf(`expected JWS POST body "{}" or "", got %q`, bodyStr)
	}
	return nil
}
