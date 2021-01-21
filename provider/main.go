package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

const (
	ISSUER           = "http://localhost:4000"
	TOKEN_EXPIRES_IN = 7 * 24 * 60 * 60
)

type AuthRequest struct {
	ResponseType string `form:"response_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	Scope        string `form:"scope"`
	State        string `form:"state"`
	Nonce        string `form:"nonce"`
}

type TokenRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	ClientID    string `form:"client_id" binding:"required"`
	RedirectURI string `form:"redirect_uri"`
	Code        string `form:"code" binding:"required"`
}

func main() {
	r := gin.Default()

	jwtManager, err := NewJWTManagerFromFile(ISSUER, "rsa.pem", "rsa.key")
	if err != nil {
		log.Fatal(err)
	}

	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"issuer":                                ISSUER,
			"authorization_endpoint":                fmt.Sprintf("%s/auth", ISSUER),
			"token_endpoint":                        fmt.Sprintf("%s/token", ISSUER),
			"jwks_uri":                              fmt.Sprintf("%s/certs", ISSUER),
			"scopes_supported":                      []string{"openid"},
			"response_types_supported":              []string{"code" /*, "id_token", "token id_token"*/},
			"subject_types_supported":               []string{"pairwise", "public"},
			"id_token_signing_alg_values_supported": []string{"RS512"},
		})
	})

	r.GET("/auth", func(c *gin.Context) {
		var req AuthRequest
		c.Bind(&req)

		redirectURI, err := url.Parse(req.RedirectURI)
		if err != nil {
			c.String(http.StatusBadRequest, "error: redirect_uri is must be URI format")
			return
		}
		resp := redirectURI.Query()
		if req.State != "" {
			resp.Set("state", req.State)
		}

		if req.Scope != "openid" {
			resp.Set("error", "unsupported_scope")
		} else {
			switch req.ResponseType {
			case "code":
				code, err := jwtManager.CreateCode(req.ClientID, 5*60)
				if err != nil {
					log.Print(err)
					resp.Set("error", "internal_server_error")
				} else {
					resp.Set("code", code)
				}
			default:
				resp.Set("error", "unsupported_response_type")
			}
		}

		redirectURI.RawQuery = resp.Encode()
		c.Redirect(http.StatusFound, redirectURI.String())
	})

	r.POST("/token", func(c *gin.Context) {
		var req TokenRequest
		c.Bind(&req)

		switch req.GrantType {
		case "authorization_code":
			if err := jwtManager.Validate(req.Code, "CODE"); err != nil {
				log.Print(err)
				c.JSON(http.StatusOK, gin.H{
					"error": "invalid_grant",
				})
				return
			}

			at, err := jwtManager.CreateAccessTokenFromCode(req.Code, TOKEN_EXPIRES_IN)
			if err != nil {
				log.Print(err)
				c.JSON(http.StatusOK, gin.H{
					"error": "internal_server_error",
				})
				return
			}

			it, err := jwtManager.CreateIDTokenFromCode(req.Code, req.ClientID, TOKEN_EXPIRES_IN)
			if err != nil {
				log.Print(err)
				c.JSON(http.StatusOK, gin.H{
					"error": "internal_server_error",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"access_token": at,
				"id_token":     it,

				"token_type": "Bearer",

				"scope": "token id_token",

				"expires_in": TOKEN_EXPIRES_IN,
			})
		default:
			c.JSON(http.StatusOK, gin.H{
				"error": "unsupported_grant_type",
			})
		}
	})

	r.Run(":4000")
}
