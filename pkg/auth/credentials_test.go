package auth

import (
	"github.com/judy2k/nexmo/internal/auth"
	"testing"
)

func TestSignatureCredentialsDefaultsToMD5Hash(t *testing.T) {
	creds := auth.SignatureCredentials{
		APIKey: "abcde",
		SignatureSecret: []byte("notasecretanymore"),
	}
	if creds.Method != Md5Hash {
		t.Errorf("Default SignatureCredentials.Method should be Md5Hash, instead was %v", creds.Method)
	}
}
