package auth

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/judy2k/nexmo/internal/auth"
)

type CredentialsCollection struct {
	secretCredentials      auth.SecretCredentials
	signatureCredentials   auth.SignatureCredentials
	applicationCredentials auth.ApplicationCredentials
}

func (c *CredentialsCollection) SecretCredentials(apiKey, secret string) {
	c.secretCredentials = auth.SecretCredentials{
		APIKey: apiKey,
		Secret: secret,
	}
}

func (c *CredentialsCollection) SignatureCredentials(apiKey, signatureSecret string, method SignatureMethod) {
	c.signatureCredentials = auth.SignatureCredentials{
		APIKey:          apiKey,
		SignatureSecret: []byte(signatureSecret),
		Method:          method,
	}
}

func (c *CredentialsCollection) ApplicationCredentials(applicationID string, privateKey []byte) (error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return err
	}
	c.applicationCredentials = auth.ApplicationCredentials{
		ApplicationID: applicationID,
		PrivateKey:    key,
	}
	return nil
}
