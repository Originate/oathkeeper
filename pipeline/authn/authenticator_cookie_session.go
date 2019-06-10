package authn

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
)

type AuthenticatorCookieSessionConfiguration struct {
	CookieName         string `json:"session_cookie_name"`
	SessionStoreOrigin string `json:"session_store_origin"`
}

type AuthenticatorCookieSession struct {
	c configuration.Provider
}

func NewAuthenticatorCookieSession(c configuration.Provider) *AuthenticatorCookieSession {
	return &AuthenticatorCookieSession{
		c: c,
	}
}

func (a *AuthenticatorCookieSession) GetID() string {
	return "cookie_session"
}

func (a *AuthenticatorCookieSession) Validate() error {
	if !a.c.AuthenticatorCookieSessionIsEnabled() {
		return errors.WithStack(ErrAuthenticatorNotEnabled.WithReasonf(`Authenticator "%s" is disabled per configuration.`, a.GetID()))
	}

	return nil
}

func (a *AuthenticatorCookieSession) Authenticate(r *http.Request, config json.RawMessage, _ pipeline.Rule) (*AuthenticationSession, error) {
	var cf AuthenticatorCookieSessionConfiguration

	if len(config) == 0 {
		config = []byte("{}")
	}

	d := json.NewDecoder(bytes.NewBuffer(config))
	d.DisallowUnknownFields()
	if err := d.Decode(&cf); err != nil {
		return nil, errors.WithStack(err)
	}

	sessionCookie, err := r.Cookie(cf.CookieName)
	if err != nil {
		return nil, errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	subject, extra, err := getSession(cf, sessionCookie.Value)
	if err != nil {
		return nil, helper.ErrForbidden.WithReason(err.Error()).WithTrace(err)
	}

	return &AuthenticationSession{
		Subject: subject,
		Extra:   extra,
	}, nil
}

func getSession(cf AuthenticatorCookieSessionConfiguration, sessionId string) (string, map[string]interface{}, error) {
	resp, err := http.Get(cf.SessionStoreOrigin + "/sessions/" + sessionId)
	if err != nil {
		return "", nil, err
	}

	if resp.StatusCode != 200 {
		return "", nil, errors.New("Session not found")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	var session struct {
		Subject string                 `json:"subject"`
		Extra   map[string]interface{} `json:"extra"`
	}
	err = json.Unmarshal(body, &session)
	if err != nil {
		return "", nil, err
	}

	return session.Subject, session.Extra, nil
}
