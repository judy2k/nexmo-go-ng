package auth

import (
	"github.com/judy2k/nexmo/internal/requestbuilder"
)

type AuthMethod func (Credentials, *requestbuilder.RequestBuilder)


func SignatureAuthMethod(c Credentials, request *requestbuilder.RequestBuilder) bool {
	_, ok := c.(SignatureCredentials)
	if ok {
		//addSignature(request.Params)
	}
	return ok
}
