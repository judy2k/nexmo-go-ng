package auth

import (
	"crypto/rsa"
	"github.com/judy2k/nexmo/pkg/auth"
)

type SecretCredentials struct {
	APIKey string
	Secret string
}

type SignatureCredentials struct {
	APIKey          string
	SignatureSecret []byte
	Method          auth.SignatureMethod
}

type ApplicationCredentials struct {
	ApplicationID string
	PrivateKey    *rsa.PrivateKey
	random        RandomProvider
}