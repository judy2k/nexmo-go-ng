package auth

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"strconv"
	"time"
)

type RandomProvider interface {
	Int31() int32
}

type jwtClaims struct {
	ApplicationID string `json:"application_id"`
	jwt.StandardClaims
}


func generateJWT(applicationID string, privateKey rsa.PrivateKey, randomProvider RandomProvider) (string, error) {
	claims := jwtClaims{
		applicationID,
		jwt.StandardClaims{
			Id:       strconv.Itoa(int(randomProvider.Int31())),
			IssuedAt: time.Now().UTC().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	return token.SignedString(privateKey)
}