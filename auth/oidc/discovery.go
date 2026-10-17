package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

const (
	maxMetadataBytes = 32 << 10
	discoveryTimeout = 5 * time.Second
)

// Configuration contains vetted endpoints and a snapshot of signing keys.
// It is immutable after construction. Refresh by calling Discover again.
type Configuration struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	IntrospectionEndpoint string
	Verifier              *Verifier
	validUntil            time.Time
}

type metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// Discover retrieves OIDC metadata and JWKS for one operator-pinned issuer.
// It rejects redirects and cross-origin endpoints, bounds both responses, and
// applies a five-second total deadline. If client is nil, the standard TLS
// verifier is used. A custom client's transport must retain TLS verification.
// The caller controls refresh and cache lifetime; this function does not cache.
func Discover(ctx context.Context, issuer, clientID string, client *http.Client) (*Configuration, error) {
	if ctx == nil || !validIssuer(issuer) || clientID == "" {
		return nil, errors.New("invalid OIDC discovery configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	if client == nil {
		client = http.DefaultClient
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var meta metadata
	if err := fetchJSON(ctx, &copyClient, issuer+"/.well-known/openid-configuration", maxMetadataBytes, &meta); err != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	if meta.Issuer != issuer || !sameOriginEndpoint(issuer, meta.AuthorizationEndpoint) ||
		!sameOriginEndpoint(issuer, meta.TokenEndpoint) || !sameOriginEndpoint(issuer, meta.JWKSURI) ||
		(meta.IntrospectionEndpoint != "" && !sameOriginEndpoint(issuer, meta.IntrospectionEndpoint)) ||
		!slices.Contains(meta.ResponseTypesSupported, "code") ||
		!slices.Contains(meta.CodeChallengeMethodsSupported, "S256") ||
		!slices.Contains(meta.IDTokenSigningAlgValuesSupported, "RS256") {
		return nil, errors.New("OIDC discovery metadata is invalid")
	}
	var jwks json.RawMessage
	if err := fetchJSON(ctx, &copyClient, meta.JWKSURI, maxJWKSBytes, &jwks); err != nil {
		return nil, errors.New("OIDC JWKS fetch failed")
	}
	verifier, err := NewVerifier(issuer, clientID, jwks)
	if err != nil {
		return nil, errors.New("OIDC JWKS is invalid")
	}
	return &Configuration{AuthorizationEndpoint: meta.AuthorizationEndpoint, TokenEndpoint: meta.TokenEndpoint, IntrospectionEndpoint: meta.IntrospectionEndpoint, Verifier: verifier, validUntil: time.Now().Add(time.Hour)}, nil
}

func sameOriginEndpoint(issuer, endpoint string) bool {
	base, _ := url.Parse(issuer)
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.Path != "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

func fetchJSON(ctx context.Context, client *http.Client, address string, limit int64, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("unexpected HTTP status")
	}
	limited := io.LimitReader(response.Body, limit+1)
	contents, err := io.ReadAll(limited)
	if err != nil || int64(len(contents)) > limit {
		return errors.New("OIDC response is too large")
	}
	if err := json.Unmarshal(contents, destination); err != nil {
		return err
	}
	return nil
}
