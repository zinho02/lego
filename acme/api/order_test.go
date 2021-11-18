package api

import (
	"crypto/pqc"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/acme"
	"github.com/zinho02/lego/v4/platform/tester"
	jose "gopkg.in/square/go-jose.v2"
)

func TestOrderService_New(t *testing.T) {
	mux, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	// small value keeps test fast
	privateKey, errK := pqc.GenerateKey("dilithium5")
	require.NoError(t, errK, "Could not generate test key")

	mux.HandleFunc("/newOrder", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		body, err := readSignedBody(r, privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		order := acme.Order{}
		err = json.Unmarshal(body, &order)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = tester.WriteJSONResponse(w, acme.Order{
			Status:      acme.StatusValid,
			Identifiers: order.Identifiers,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	core, err := New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	order, err := core.Orders.New([]string{"example.com"})
	require.NoError(t, err)

	expected := acme.ExtendedOrder{
		Order: acme.Order{
			Status:      "valid",
			Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		},
	}
	assert.Equal(t, expected, order)
}

func BenchmarkOrderService_New(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				mux, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				// small value keeps test fast
				privateKey, errK := pqc.GenerateKey(v.input)
				require.NoError(b, errK, "Could not generate test key")

				mux.HandleFunc("/newOrder", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
						return
					}

					body, err := readSignedBody(r, privateKey)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
					}

					order := acme.Order{}
					err = json.Unmarshal(body, &order)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}

					err = tester.WriteJSONResponse(w, acme.Order{
						Status:      acme.StatusValid,
						Identifiers: order.Identifiers,
					})
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				})

				core, err := New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
				require.NoError(b, err)

				order, err := core.Orders.New([]string{"example.com"})
				require.NoError(b, err)

				expected := acme.ExtendedOrder{
					Order: acme.Order{
						Status:      "valid",
						Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
					},
				}
				assert.Equal(b, expected, order)
			}
		})
	}
}

func readSignedBody(r *http.Request, privateKey *pqc.PrivateKey) ([]byte, error) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	jws, err := jose.ParseSigned(string(reqBody))
	if err != nil {
		return nil, err
	}

	body, err := jws.Verify(&jose.JSONWebKey{
		Key:       privateKey.Public(),
		Algorithm: "RainbowVClassic",
	})
	if err != nil {
		return nil, err
	}

	return body, nil
}
