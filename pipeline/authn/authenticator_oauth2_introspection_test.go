/*
 * Copyright © 2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author       Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright  2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license  	   Apache-2.0
 */

package authn_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/internal"
	. "github.com/ory/oathkeeper/pipeline/authn"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorOAuth2Introspection(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistry(conf)

	a, err := reg.PipelineAuthenticator("oauth2_introspection")
	require.NoError(t, err)
	assert.Equal(t, "oauth2_introspection", a.GetID())

	t.Run("method=authenticate", func(t *testing.T) {

		for k, tc := range []struct {
			d          string
			setup      func(*testing.T, *httprouter.Router)
			r          *http.Request
			config     json.RawMessage
			expectErr  bool
			expectSess *AuthenticationSession
		}{
			{
				d:         "should fail because no payloads",
				r:         &http.Request{Header: http.Header{}},
				expectErr: true,
			},
			{
				d:      "should fail because wrong response",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a", "scope-b"] }`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.Equal(t, "scope-a scope-b", r.Form.Get("scope"))
						w.WriteHeader(http.StatusNotFound)
					})
				},
				expectErr: true,
			},
			{
				d:      "should fail because not active",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   false,
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "issuer",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: true,
			},
			{
				d:      "should pass because active and no issuer / audience expected",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "issuer",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: false,
			},
			{
				d:      "should pass because active and scope matching",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a", "scope-b"] }`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.Equal(t, "scope-a scope-b", r.Form.Get("scope"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "issuer",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
							Scope:    "scope-a scope-b",
						}))
					})
				},
				expectErr: false,
			},
			{
				d:      "should fail because active but scope not matching",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a", "scope-b", "scope-c"] }`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "token", r.Form.Get("token"))
						require.Equal(t, "scope-a scope-b scope-c", r.Form.Get("scope"))
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "issuer",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
							Scope:    "scope-a scope-b",
						}))
					})
				},
				expectErr: true,
			},
			{
				d:      "should fail because active but issuer not matching",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a"], "trusted_issuers": ["foo", "bar"]}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Scope:    "scope-a",
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "not-foo",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: true,
			},
			{
				d:      "should pass because active and issuer matching",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a"], "trusted_issuers": ["foo", "bar"]}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Scope:    "scope-a",
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "foo",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: false,
			},
			{
				d:      "should fail because active but audience not matching",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a"], "trusted_issuers": ["foo", "bar"], "target_audience": ["audience"] }`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Scope:    "scope-a",
							Subject:  "subject",
							Audience: []string{"not-audience"},
							Issuer:   "foo",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: true,
			},
			{
				d:      "should pass",
				r:      &http.Request{Header: http.Header{"Authorization": {"bearer token"}}},
				config: []byte(`{ "required_scope": ["scope-a"], "trusted_issuers": ["foo", "bar"], "target_audience": ["audience"] }`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.NoError(t, json.NewEncoder(w).Encode(&AuthenticatorOAuth2IntrospectionResult{
							Active:   true,
							Scope:    "scope-a",
							Subject:  "subject",
							Audience: []string{"audience"},
							Issuer:   "foo",
							Username: "username",
							Extra:    map[string]interface{}{"extra": "foo"},
						}))
					})
				},
				expectErr: false,
			},
		} {
			t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
				router := httprouter.New()
				if tc.setup != nil {
					tc.setup(t, router)
				}
				ts := httptest.NewServer(router)
				defer ts.Close()

				viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIntrospectionURL, ts.URL+"/oauth2/introspect")
				viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionScopeStrategy, "exact")
				sess, err := a.Authenticate(tc.r, tc.config, nil)
				if tc.expectErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}

				if tc.expectSess != nil {
					assert.Equal(t, tc.expectSess, sess)
				}
			})
		}
	})

	t.Run("method=validate", func(t *testing.T) {
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, false)
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIntrospectionURL, "")
		require.Error(t, a.Validate())

		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, true)
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIntrospectionURL, "")
		require.Error(t, a.Validate())

		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, false)
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIntrospectionURL, "/oauth2/token")
		require.Error(t, a.Validate())

		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIsEnabled, true)
		viper.Set(configuration.ViperKeyAuthenticatorOAuth2TokenIntrospectionIntrospectionURL, "/oauth2/token")
		require.NoError(t, a.Validate())
	})
}
