package auth

import (
	"github.com/judy2k/nexmo/internal/requestbuilder"
	"github.com/judy2k/nexmo/pkg/auth"
)

type AuthMethod func(auth.Credentials, *requestbuilder.RequestBuilder)

// Secret auth in body params
// Secret auth in url params (maybe even in POST request, as opposed to in the body)
// Secret auth in body JSON
func SecretAuth(c auth.Credentials, request *requestbuilder.RequestBuilder) bool {
	panic("SecretAuth is not yet implemented!")
	return true
}

// Basic auth (with secret, in header)
func BasicAuth(c auth.Credentials, request *requestbuilder.RequestBuilder) bool {
	panic("BasicAuth is not yet implemented!")
	return true
}

// Signature auth in body params
func SignatureAuthMethod(c auth.Credentials, request *requestbuilder.RequestBuilder) bool {
	signatureCredentials, ok := c.(auth.signatureCredentials)
	if ok {
		auth.Sign(request.Params, []byte(signatureCredentials.SignatureSecret), signatureCredentials.Method)
	}
	return ok
}

// JWT Auth - (generated token in header)
func JWTAuth(c auth.Credentials, request *requestbuilder.RequestBuilder) bool {
	panic("BasicAuth is not yet implemented!")
	return true
}

// OAuth (who the hell knows?)
