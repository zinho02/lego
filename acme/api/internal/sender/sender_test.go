package sender

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDo_UserAgentOnAllHTTPMethod(t *testing.T) {
	var ua, method string
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		method = r.Method
	}))
	defer ts.Close()

	doer := NewDoer(http.DefaultClient, "")

	testCases := []struct {
		method string
		call   func(u string) (*http.Response, error)
	}{
		{
			method: http.MethodGet,
			call: func(u string) (*http.Response, error) {
				return doer.Get(u, nil)
			},
		},
		{
			method: http.MethodHead,
			call:   doer.Head,
		},
		{
			method: http.MethodPost,
			call: func(u string) (*http.Response, error) {
				return doer.Post(u, strings.NewReader("falalalala"), "text/plain", nil)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.method, func(t *testing.T) {
			_, err := test.call(ts.URL)
			require.NoError(t, err)

			assert.Equal(t, test.method, method)
			assert.Contains(t, ua, ourUserAgent, "User-Agent")
		})
	}
}

func BenchmarkDo_UserAgentOnAllHTTPMethod(b *testing.B) {
	for n := 0; n < b.N; n++ {
		var ua, method string
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			ua = r.Header.Get("User-Agent")
			method = r.Method
		}))
		defer ts.Close()

		doer := NewDoer(http.DefaultClient, "")

		testCases := []struct {
			method string
			call   func(u string) (*http.Response, error)
		}{
			{
				method: http.MethodGet,
				call: func(u string) (*http.Response, error) {
					return doer.Get(u, nil)
				},
			},
			{
				method: http.MethodHead,
				call:   doer.Head,
			},
			{
				method: http.MethodPost,
				call: func(u string) (*http.Response, error) {
					return doer.Post(u, strings.NewReader("falalalala"), "text/plain", nil)
				},
			},
		}

		for _, test := range testCases {
			b.Run(test.method, func(b *testing.B) {
				_, err := test.call(ts.URL)
				require.NoError(b, err)

				assert.Equal(b, test.method, method)
				assert.Contains(b, ua, ourUserAgent, "User-Agent")
			})
		}
	}
}

func TestDo_CustomUserAgent(t *testing.T) {
	customUA := "MyApp/1.2.3"
	doer := NewDoer(http.DefaultClient, customUA)

	ua := doer.formatUserAgent()
	assert.Contains(t, ua, ourUserAgent)
	assert.Contains(t, ua, customUA)
	if strings.HasSuffix(ua, " ") {
		t.Errorf("UA should not have trailing spaces; got '%s'", ua)
	}
	assert.Len(t, strings.Split(ua, " "), 5)
}

func BenchmarkDo_CustomUserAgent(b *testing.B) {
	for n := 0; n < b.N; n++ {
		customUA := "MyApp/1.2.3"
		doer := NewDoer(http.DefaultClient, customUA)

		ua := doer.formatUserAgent()
		assert.Contains(b, ua, ourUserAgent)
		assert.Contains(b, ua, customUA)
		if strings.HasSuffix(ua, " ") {
			b.Errorf("UA should not have trailing spaces; got '%s'", ua)
		}
		assert.Len(b, strings.Split(ua, " "), 5)
	}
}
