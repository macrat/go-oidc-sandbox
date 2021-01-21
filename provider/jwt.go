package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type OIDCClaims struct {
	jwt.StandardClaims

	Type string `json:"typ"`
}

func ReadPublicKey(filename string) (*rsa.PublicKey, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM(raw)
}

func ReadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(raw)
}

type JWTManager struct {
	Issuer  string
	public  *rsa.PublicKey
	private *rsa.PrivateKey
}

func NewJWTManagerFromFile(issuer, publicFile, privateFile string) (JWTManager, error) {
	pub, err := ReadPublicKey(publicFile)
	if err != nil {
		return JWTManager{}, err
	}

	pri, err := ReadPrivateKey(privateFile)
	if err != nil {
		return JWTManager{}, err
	}

	return JWTManager{
		Issuer:  issuer,
		public:  pub,
		private: pri,
	}, nil
}

func (m JWTManager) create(type_ string, subject string, audience string, expiresIn int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, OIDCClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    m.Issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: time.Now().Unix() + expiresIn,
			IssuedAt:  time.Now().Unix(),
		},
		Type: type_,
	})

	return token.SignedString(m.private)
}

func (m JWTManager) CreateCode(subject string, expiresIn int64) (string, error) {
	return m.create("CODE", subject, m.Issuer, expiresIn)
}

func (m JWTManager) CreateAccessToken(subject string, expiresIn int64) (string, error) {
	return m.create("ACCESS_TOKEN", subject, m.Issuer, expiresIn)
}

func (m JWTManager) CreateAccessTokenFromCode(code string, expiresIn int64) (string, error) {
	_, claims, err := m.parse(code)
	if err != nil {
		return "", err
	}

	return m.CreateAccessToken(claims.Subject, expiresIn)
}

func (m JWTManager) CreateIDToken(issuer, subject string, expiresIn int64) (string, error) {
	return m.create("ACCESS_TOKEN", subject, issuer, expiresIn)
}

func (m JWTManager) CreateIDTokenFromCode(code, issuer string, expiresIn int64) (string, error) {
	_, claims, err := m.parse(code)
	if err != nil {
		return "", err
	}

	return m.CreateIDToken(issuer, claims.Subject, expiresIn)
}

func (m JWTManager) parse(token string) (*jwt.Token, OIDCClaims, error) {
	var claims OIDCClaims

	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return m.public, nil
	})

	if !parsed.Valid {
		return nil, OIDCClaims{}, fmt.Errorf("invalid token")
	}
	return parsed, claims, err
}

func (m JWTManager) Validate(token string, expectType string) error {
	_, claims, err := m.parse(token)
	if err != nil {
		return err
	}

	if claims.Type != expectType {
		return fmt.Errorf("unexpected type")
	}
	if claims.Issuer != m.Issuer {
		return fmt.Errorf("unexpected issuer")
	}

	return nil
}
