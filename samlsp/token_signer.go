package samlsp

import (
	"context"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

// AuthorizationTokenSigner implements signing for authorization tokens
type AuthorizationTokenSigner interface {
	// ParseAuthorizationToken returns an authorization token if tokenStr is a valid serialized token
	// produced by MarshalAuthorizationToken.
	ParseAuthorizationToken(ctx context.Context, tokenStr string) (*AuthorizationToken, error)

	// MarshalAuthorizationToken marshals and signs the token returning the serialized token
	MarshalAuthorizationToken(ctx context.Context, token AuthorizationToken) (string, error)
}

// JWTTokenSigner implements AuthorizationTokenSigner using JWT
type JWTTokenSigner struct {
	Key      []byte
	Audience string
}

// ParseAuthorizationToken returns a token from a JWT encoded & signed token.
func (j JWTTokenSigner) ParseAuthorizationToken(ctx context.Context, tokenStr string) (*AuthorizationToken, error) {
	claims := AuthorizationToken{}
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return j.Key, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if err := claims.StandardClaims.Valid(); err != nil {
		return nil, err
	}

	if claims.Audience != j.Audience {
		return nil, fmt.Errorf("incorrect audience: %v", claims.Audience)
	}

	return &claims, nil
}

// MarshalAuthorizationToken marshals and signs the token returning the serialized token
func (j JWTTokenSigner) MarshalAuthorizationToken(ctx context.Context, token AuthorizationToken) (string, error) {
	signedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, token).SignedString(j.Key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
