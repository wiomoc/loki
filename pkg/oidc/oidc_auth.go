package oidc

import (
	oidc "github.com/coreos/go-oidc"
	"github.com/weaveworks/common/user"
	"golang.org/x/net/context"
	"net/http"
	"strings"
)

type OIDCHTTPAuthMiddleware struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCHTTPAuthMiddleware(issuerURL string) (*OIDCHTTPAuthMiddleware, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	return &OIDCHTTPAuthMiddleware{
		provider.Verifier(oidcConfig),
	}, nil
}

func (o *OIDCHTTPAuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = user.InjectOrgID(ctx, "fake")

		// Skip auth for push
		if r.URL.Path != "/api/prom/push" && r.URL.Path != "/loki/api/v1/push" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			token, err := o.verifier.Verify(ctx, strings.TrimSpace(strings.TrimLeft(authHeader, "Bearer")))
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ctx = user.InjectUserID(ctx, token.Subject)

			var claims map[string]interface{}
			err = token.Claims(&claims)
			if err == nil {
				ctx = context.WithValue(ctx, "matcher", claims["matcher"])
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
