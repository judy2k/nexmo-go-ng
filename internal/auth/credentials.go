package auth

type Credentials interface{}

type SecretCredentials struct {
	APIKey string
	Secret string
}

type SignatureCredentials struct {
	APIKey          string
	SignatureSecret string
}

type ApplicationCredentials struct {
	ApplicationID string
	PrivateKey    string
}
