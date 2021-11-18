package http01

import (
	"crypto/pqc"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zinho02/lego/v4/acme"
	"github.com/zinho02/lego/v4/acme/api"
	"github.com/zinho02/lego/v4/challenge"
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

func TestChallenge(t *testing.T) {
	_, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	providerServer := NewProviderServer("", "23457")

	validate := func(_ *api.Core, _ string, chlng acme.Challenge) error {
		uri := "http://localhost" + providerServer.GetAddress() + ChallengePath(chlng.Token)

		resp, err := http.DefaultClient.Get(uri)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			t.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			t.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:23457",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http1"},
		},
	}

	err = solver.Solve(authz)
	require.NoError(t, err)
}

func BenchmarkChallenge(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				providerServer := NewProviderServer("", "23457")

				validate := func(_ *api.Core, _ string, chlng acme.Challenge) error {
					uri := "http://localhost" + providerServer.GetAddress() + ChallengePath(chlng.Token)

					resp, err := http.DefaultClient.Get(uri)
					if err != nil {
						return err
					}
					defer resp.Body.Close()

					if want := "text/plain"; resp.Header.Get("Content-Type") != want {
						b.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
					}

					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return err
					}
					bodyStr := string(body)

					if bodyStr != chlng.KeyAuthorization {
						b.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
					}

					return nil
				}

				privateKey, err := pqc.GenerateKey(v.input)
				require.NoError(b, err, "Could not generate test key")

				core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
				require.NoError(b, err)

				solver := NewChallenge(core, validate, providerServer)

				authz := acme.Authorization{
					Identifier: acme.Identifier{
						Value: "localhost:23457",
					},
					Challenges: []acme.Challenge{
						{Type: challenge.HTTP01.String(), Token: "http1"},
					},
				}

				err = solver.Solve(authz)
				require.NoError(b, err)
			}
		})
	}
}

func TestChallengeInvalidPort(t *testing.T) {
	_, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	privateKey, err := rsa.GenerateKey(rand.Reader, 128)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	validate := func(_ *api.Core, _ string, _ acme.Challenge) error { return nil }

	solver := NewChallenge(core, validate, NewProviderServer("", "123456"))

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:123456",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http2"},
		},
	}

	err = solver.Solve(authz)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
	assert.Contains(t, err.Error(), "123456")
}

func BenchmarkChallengeInvalidPort(b *testing.B) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				_, apiURL, tearDown := tester.SetupFakeAPI()
				defer tearDown()

				privateKey, err := pqc.GenerateKey(v.input)
				require.NoError(b, err, "Could not generate test key")

				core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
				require.NoError(b, err)

				validate := func(_ *api.Core, _ string, _ acme.Challenge) error { return nil }

				solver := NewChallenge(core, validate, NewProviderServer("", "123456"))

				authz := acme.Authorization{
					Identifier: acme.Identifier{
						Value: "localhost:123456",
					},
					Challenges: []acme.Challenge{
						{Type: challenge.HTTP01.String(), Token: "http2"},
					},
				}

				err = solver.Solve(authz)
				require.Error(b, err)
				assert.Contains(b, err.Error(), "invalid port")
				assert.Contains(b, err.Error(), "123456")
			}
		})
	}
}

type testProxyHeader struct {
	name   string
	values []string
}

func (h *testProxyHeader) update(r *http.Request) {
	if h == nil || len(h.values) == 0 {
		return
	}
	if h.name == "Host" {
		r.Host = h.values[0]
	} else if h.name != "" {
		r.Header[h.name] = h.values
	}
}

func TestChallengeWithProxy(t *testing.T) {
	h := func(name string, values ...string) *testProxyHeader {
		name = textproto.CanonicalMIMEHeaderKey(name)
		return &testProxyHeader{name, values}
	}

	const (
		ok   = "localhost:23457"
		nook = "example.com"
	)

	testCases := []struct {
		name   string
		header *testProxyHeader
		extra  *testProxyHeader
		isErr  bool
	}{
		// tests for hostMatcher
		{
			name: "no proxy",
		},
		{
			name:   "empty string",
			header: h(""),
		},
		{
			name:   "empty Host",
			header: h("host"),
		},
		{
			name:   "matching Host",
			header: h("host", ok),
		},
		{
			name:   "Host mismatch",
			header: h("host", nook),
			isErr:  true,
		},
		{
			name:   "Host mismatch (ignoring forwarding header)",
			header: h("host", nook),
			extra:  h("X-Forwarded-Host", ok),
			isErr:  true,
		},
		// test for arbitraryMatcher
		{
			name:   "matching X-Forwarded-Host",
			header: h("X-Forwarded-Host", ok),
		},
		{
			name:   "matching X-Forwarded-Host (multiple fields)",
			header: h("X-Forwarded-Host", ok, nook),
		},
		{
			name:   "matching X-Forwarded-Host (chain value)",
			header: h("X-Forwarded-Host", ok+", "+nook),
		},
		{
			name:   "X-Forwarded-Host mismatch",
			header: h("X-Forwarded-Host", nook),
			extra:  h("host", ok),
			isErr:  true,
		},
		{
			name:   "X-Forwarded-Host mismatch (multiple fields)",
			header: h("X-Forwarded-Host", nook, ok),
			isErr:  true,
		},
		{
			name:   "matching X-Something-Else",
			header: h("X-Something-Else", ok),
		},
		{
			name:   "matching X-Something-Else (multiple fields)",
			header: h("X-Something-Else", ok, nook),
		},
		{
			name:   "matching X-Something-Else (chain value)",
			header: h("X-Something-Else", ok+", "+nook),
		},
		{
			name:   "X-Something-Else mismatch",
			header: h("X-Something-Else", nook),
			isErr:  true,
		},
		{
			name:   "X-Something-Else mismatch (multiple fields)",
			header: h("X-Something-Else", nook, ok),
			isErr:  true,
		},
		{
			name:   "X-Something-Else mismatch (chain value)",
			header: h("X-Something-Else", nook+", "+ok),
			isErr:  true,
		},
		// tests for forwardedHeader
		{
			name:   "matching Forwarded",
			header: h("Forwarded", fmt.Sprintf("host=%q;foo=bar", ok)),
		},
		{
			name:   "matching Forwarded (multiple fields)",
			header: h("Forwarded", fmt.Sprintf("host=%q", ok), "host="+nook),
		},
		{
			name:   "matching Forwarded (chain value)",
			header: h("Forwarded", fmt.Sprintf("host=%q, host=%s", ok, nook)),
		},
		{
			name:   "Forwarded mismatch",
			header: h("Forwarded", "host="+nook),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (missing information)",
			header: h("Forwarded", "for=127.0.0.1"),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (multiple fields)",
			header: h("Forwarded", "host="+nook, fmt.Sprintf("host=%q", ok)),
			isErr:  true,
		},
		{
			name:   "Forwarded mismatch (chain value)",
			header: h("Forwarded", fmt.Sprintf("host=%s, host=%q", nook, ok)),
			isErr:  true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			testServeWithProxy(t, test.header, test.extra, test.isErr)
		})
	}
}

func BenchmarkChallengeWithProxy(b *testing.B) {
	for n := 0; n < b.N; n++ {
		h := func(name string, values ...string) *testProxyHeader {
			name = textproto.CanonicalMIMEHeaderKey(name)
			return &testProxyHeader{name, values}
		}

		const (
			ok   = "localhost:23457"
			nook = "example.com"
		)

		testCases := []struct {
			name   string
			header *testProxyHeader
			extra  *testProxyHeader
			isErr  bool
		}{
			// tests for hostMatcher
			{
				name: "no proxy",
			},
			{
				name:   "empty string",
				header: h(""),
			},
			{
				name:   "empty Host",
				header: h("host"),
			},
			{
				name:   "matching Host",
				header: h("host", ok),
			},
			{
				name:   "Host mismatch",
				header: h("host", nook),
				isErr:  true,
			},
			{
				name:   "Host mismatch (ignoring forwarding header)",
				header: h("host", nook),
				extra:  h("X-Forwarded-Host", ok),
				isErr:  true,
			},
			// test for arbitraryMatcher
			{
				name:   "matching X-Forwarded-Host",
				header: h("X-Forwarded-Host", ok),
			},
			{
				name:   "matching X-Forwarded-Host (multiple fields)",
				header: h("X-Forwarded-Host", ok, nook),
			},
			{
				name:   "matching X-Forwarded-Host (chain value)",
				header: h("X-Forwarded-Host", ok+", "+nook),
			},
			{
				name:   "X-Forwarded-Host mismatch",
				header: h("X-Forwarded-Host", nook),
				extra:  h("host", ok),
				isErr:  true,
			},
			{
				name:   "X-Forwarded-Host mismatch (multiple fields)",
				header: h("X-Forwarded-Host", nook, ok),
				isErr:  true,
			},
			{
				name:   "matching X-Something-Else",
				header: h("X-Something-Else", ok),
			},
			{
				name:   "matching X-Something-Else (multiple fields)",
				header: h("X-Something-Else", ok, nook),
			},
			{
				name:   "matching X-Something-Else (chain value)",
				header: h("X-Something-Else", ok+", "+nook),
			},
			{
				name:   "X-Something-Else mismatch",
				header: h("X-Something-Else", nook),
				isErr:  true,
			},
			{
				name:   "X-Something-Else mismatch (multiple fields)",
				header: h("X-Something-Else", nook, ok),
				isErr:  true,
			},
			{
				name:   "X-Something-Else mismatch (chain value)",
				header: h("X-Something-Else", nook+", "+ok),
				isErr:  true,
			},
			// tests for forwardedHeader
			{
				name:   "matching Forwarded",
				header: h("Forwarded", fmt.Sprintf("host=%q;foo=bar", ok)),
			},
			{
				name:   "matching Forwarded (multiple fields)",
				header: h("Forwarded", fmt.Sprintf("host=%q", ok), "host="+nook),
			},
			{
				name:   "matching Forwarded (chain value)",
				header: h("Forwarded", fmt.Sprintf("host=%q, host=%s", ok, nook)),
			},
			{
				name:   "Forwarded mismatch",
				header: h("Forwarded", "host="+nook),
				isErr:  true,
			},
			{
				name:   "Forwarded mismatch (missing information)",
				header: h("Forwarded", "for=127.0.0.1"),
				isErr:  true,
			},
			{
				name:   "Forwarded mismatch (multiple fields)",
				header: h("Forwarded", "host="+nook, fmt.Sprintf("host=%q", ok)),
				isErr:  true,
			},
			{
				name:   "Forwarded mismatch (chain value)",
				header: h("Forwarded", fmt.Sprintf("host=%s, host=%q", nook, ok)),
				isErr:  true,
			},
		}

		for _, test := range testCases {
			b.Run(test.name, func(b *testing.B) {
				benchmarkServeWithProxy(b, test.header, test.extra, test.isErr)
			})
		}
	}
}

func testServeWithProxy(t *testing.T, header, extra *testProxyHeader, expectError bool) {
	t.Helper()

	_, apiURL, tearDown := tester.SetupFakeAPI()
	defer tearDown()

	providerServer := NewProviderServer("localhost", "23457")
	if header != nil {
		providerServer.SetProxyHeader(header.name)
	}

	validate := func(_ *api.Core, _ string, chlng acme.Challenge) error {
		uri := "http://" + providerServer.GetAddress() + ChallengePath(chlng.Token)

		req, err := http.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			return err
		}
		header.update(req)
		extra.update(req)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if want := "text/plain"; resp.Header.Get("Content-Type") != want {
			return fmt.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		bodyStr := string(body)

		if bodyStr != chlng.KeyAuthorization {
			return fmt.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
		}

		return nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
	require.NoError(t, err)

	solver := NewChallenge(core, validate, providerServer)

	authz := acme.Authorization{
		Identifier: acme.Identifier{
			Value: "localhost:23457",
		},
		Challenges: []acme.Challenge{
			{Type: challenge.HTTP01.String(), Token: "http1"},
		},
	}

	err = solver.Solve(authz)
	if expectError {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}

func benchmarkServeWithProxy(b *testing.B, header, extra *testProxyHeader, expectError bool) {
	for _, v := range table {
		b.Run(v.input, func(b *testing.B) {
			b.Helper()

			_, apiURL, tearDown := tester.SetupFakeAPI()
			defer tearDown()

			providerServer := NewProviderServer("localhost", "23457")
			if header != nil {
				providerServer.SetProxyHeader(header.name)
			}

			validate := func(_ *api.Core, _ string, chlng acme.Challenge) error {
				uri := "http://" + providerServer.GetAddress() + ChallengePath(chlng.Token)

				req, err := http.NewRequest(http.MethodGet, uri, nil)
				if err != nil {
					return err
				}
				header.update(req)
				extra.update(req)

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				if want := "text/plain"; resp.Header.Get("Content-Type") != want {
					return fmt.Errorf("Get(%q) Content-Type: got %q, want %q", uri, resp.Header.Get("Content-Type"), want)
				}

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				bodyStr := string(body)

				if bodyStr != chlng.KeyAuthorization {
					return fmt.Errorf("Get(%q) Body: got %q, want %q", uri, bodyStr, chlng.KeyAuthorization)
				}

				return nil
			}

			privateKey, err := pqc.GenerateKey(v.input)
			require.NoError(b, err, "Could not generate test key")

			core, err := api.New(http.DefaultClient, "lego-test", apiURL+"/dir", "", privateKey)
			require.NoError(b, err)

			solver := NewChallenge(core, validate, providerServer)

			authz := acme.Authorization{
				Identifier: acme.Identifier{
					Value: "localhost:23457",
				},
				Challenges: []acme.Challenge{
					{Type: challenge.HTTP01.String(), Token: "http1"},
				},
			}

			err = solver.Solve(authz)
			if expectError {
				require.Error(b, err)
			} else {
				require.NoError(b, err)
			}
		})
	}
}
