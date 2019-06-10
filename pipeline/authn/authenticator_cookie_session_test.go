package authn_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ory/oathkeeper/internal"
	. "github.com/ory/oathkeeper/pipeline/authn"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestRequest(sessionCookieValue string, secure bool) *http.Request {
	req := &http.Request{Header: http.Header{}}
	if sessionCookieValue != "" {
		req.AddCookie(&http.Cookie{
			Name:  "session-cookie-name",
			Value: sessionCookieValue,
		})
	}
	return req
}

func TestAuthenticatorCookieSession(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistry(conf)

	pipelineAuthenticator, err := reg.PipelineAuthenticator("cookie_session")
	require.NoError(t, err)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/sessions/valid-sess-id" {
			w.Write([]byte(`{ "subject": "sub", "extra": { "foo": "bar" } }`))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer testServer.Close()

	config, err := json.Marshal(map[string]string{
		"session_cookie_name":  "session-cookie-name",
		"session_store_origin": testServer.URL,
	})
	require.NoError(t, err)

	t.Run("method=authenticate", func(t *testing.T) {
		for k, testCase := range []struct {
			d          string
			r          *http.Request
			expectErr  bool
			expectSess *AuthenticationSession
		}{
			{
				d:         "should fail because no cookie",
				r:         generateTestRequest("", false),
				expectErr: true,
			}, {
				d:         "should fail because session not found in session store",
				r:         generateTestRequest("invalid-sess-id", true),
				expectErr: true,
			}, {
				d: "should pass because valid session cookie",
				r: generateTestRequest("valid-sess-id", true),
				expectSess: &AuthenticationSession{
					Subject: "sub",
					Extra:   map[string]interface{}{"foo": "bar"},
				},
				expectErr: false,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/description=%s", k, testCase.d), func(t *testing.T) {
				session, err := pipelineAuthenticator.Authenticate(testCase.r, json.RawMessage(config), nil)

				if testCase.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err, "%#v", errors.Cause(err))
				}

				if testCase.expectSess != nil {
					assert.Equal(t, testCase.expectSess, session)
				}
			})
		}
	})
}
