package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxIntrospectionResponseBytes = 32 << 10

// ErrIntrospectionFailed deliberately hides credentials, token contents and
// provider response details from callers and logs.
var ErrIntrospectionFailed = errors.New("OIDC token introspection failed")

// TokenStatus is the bounded, client-bound subset of RFC 7662 metadata needed
// by a relying application. An inactive token has Active=false and no trusted
// identity fields.
type TokenStatus struct {
	Active    bool
	Subject   string
	SessionID string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TokenIntrospector authenticates one confidential client against the
// same-origin endpoint vetted by Discover.
type TokenIntrospector struct {
	endpoint string
	clientID string
	secret   string
	client   http.Client
	now      func() time.Time
}

func NewTokenIntrospector(configuration *Configuration, clientID, clientSecret string, client *http.Client) (*TokenIntrospector, error) {
	if configuration == nil || configuration.Verifier == nil || clientID == "" || clientID != configuration.Verifier.clientID || clientSecret == "" ||
		!sameOriginEndpoint(configuration.Verifier.issuer, configuration.IntrospectionEndpoint) {
		return nil, errors.New("invalid OIDC introspection configuration")
	}
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &TokenIntrospector{endpoint: configuration.IntrospectionEndpoint, clientID: clientID, secret: clientSecret, client: copyClient, now: time.Now}, nil
}

// Introspect checks one opaque bearer token. Network, authentication, parsing
// and inconsistent active responses fail closed with ErrIntrospectionFailed.
func (i *TokenIntrospector) Introspect(ctx context.Context, token string) (TokenStatus, error) {
	if i == nil || ctx == nil || token == "" || len(token) > maxCodeBytes {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(i.clientID, i.secret)
	response, err := i.client.Do(request)
	if err != nil {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxIntrospectionResponseBytes+1))
	if err != nil || len(contents) > maxIntrospectionResponseBytes {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	var result struct {
		Active    bool   `json:"active"`
		ClientID  string `json:"client_id"`
		Subject   string `json:"sub"`
		SessionID string `json:"sid"`
		Scope     string `json:"scope"`
		TokenType string `json:"token_type"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(contents, &result); err != nil {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	if !result.Active {
		return TokenStatus{Active: false}, nil
	}
	now := i.now()
	issuedAt, expiresAt := time.Unix(result.IssuedAt, 0), time.Unix(result.ExpiresAt, 0)
	if result.ClientID != i.clientID || result.Subject == "" || result.SessionID == "" || !strings.EqualFold(result.TokenType, "Bearer") ||
		len(result.Subject) > 1024 || len(result.SessionID) > 1024 || len(result.Scope) > 4096 ||
		result.IssuedAt <= 0 || result.ExpiresAt <= result.IssuedAt || issuedAt.After(now.Add(clockSkew)) || !now.Before(expiresAt) || expiresAt.After(now.Add(24*time.Hour)) {
		return TokenStatus{}, ErrIntrospectionFailed
	}
	return TokenStatus{Active: true, Subject: result.Subject, SessionID: result.SessionID, Scope: result.Scope, IssuedAt: issuedAt, ExpiresAt: expiresAt}, nil
}
