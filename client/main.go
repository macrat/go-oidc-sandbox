package main

import (
	"context"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type CallbackRequest struct {
	Code string `form:"code" binding:"required"`
}

func main() {
	issuer := "http://localhost:4000"  // original provider
	//issuer := "http://localhost:8080/auth/realms/master" // KeyCloak

	provider, err := oidc.NewProvider(context.TODO(), issuer)
	if err != nil {
		log.Fatal(err)
	}
	conf := oauth2.Config{
		ClientID:     "goidc",
		ClientSecret: "hello world",
		RedirectURL:  "http://localhost:3000/login/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}

	r := gin.Default()

	r.GET("/login", func(c *gin.Context) {
		c.Redirect(http.StatusFound, conf.AuthCodeURL(uuid.New().String()))
	})

	r.GET("/login/callback", func(c *gin.Context) {
		var req CallbackRequest
		c.Bind(&req)

		token, err := conf.Exchange(c, req.Code)
		if err != nil {
			log.Print(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"code": req.Code, "token": token})
	})

	r.Run(":3000")
}
