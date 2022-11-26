package main

import (
	"context"
	"errors"
	"fmt"
	"forward-auth/config"
	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"strings"
	"time"
)

type jwksContext struct {
	ctx    *context.Context
	cancel *context.CancelFunc
	jwks   *keyfunc.JWKS
	config *config.SyncedConfig
}

type JWTClaim struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func ContainsAny[T comparable](s []T, e []T) bool {
	for _, v := range s {
		for _, v2 := range e {
			if v == v2 {
				return true
			}
		}
	}
	return false
}

func (ctx *jwksContext) authenticate(c *gin.Context) {
	rawToken := c.GetHeader("Authorization")
	method := c.GetHeader("X-Forwarded-Method")
	uri := c.GetHeader("X-Forwarded-Uri")
	ip := c.GetHeader("X-Forwarded-For")
	log.Printf("Authenticating %s:%s for %s", method, uri, ip)
	if len(rawToken) < 8 || !strings.HasPrefix(rawToken, "Bearer ") {
		fmt.Println("No token available")
		c.AbortWithStatus(401)
		return
	}
	rawToken = strings.TrimPrefix(rawToken, "Bearer ")
	if len(method) == 0 || len(uri) == 0 || len(ip) == 0 {
		fmt.Println("No traefik X variables available")
		c.AbortWithStatus(400)
		return
	}
	fmt.Printf("Authenticating request %s:%s for %s", method, uri, ip)
	claims, err := ctx.validateJwks(rawToken)
	if err != nil {
		log.Println("Request didn't contain valid token")
		c.AbortWithStatus(403)
		return
	}
	conf := ctx.config.Config
	roles := strings.Split(claims.Scope, " ")
	for _, path := range conf.Paths {
		if strings.HasPrefix(uri, path.Path) {
			log.Println("Matched prefix " + path.Path)
			if (len(path.Methods) > 0 && !Contains(path.Methods, method)) || (len(path.Scopes) > 0 && !ContainsAny(path.Scopes, roles)) {
				log.Println("Missing method or scope")
				break
			} else {
				c.Header("X-Forwarded-Roles", strings.Join(roles, ","))
				c.Header("X-Forwarded-User", claims.Subject)
				c.Status(200)
				return
			}
		}
	}
	c.AbortWithStatus(403)
}

func initializeJwks(config *config.SyncedConfig) (jwksContext, error) {
	jwksURL := config.Config.Jwt.JwksUrl
	if !strings.Contains(jwksURL, "/.well-known/jwks.json") {
		jwksURL += "/.well-known/jwks.json"
	}
	fmt.Println("Using jwks url: " + jwksURL)
	ctx, cancel := context.WithCancel(context.Background())

	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}
	cont := jwksContext{jwks: jwks, ctx: &ctx, cancel: &cancel, config: config}

	return cont, nil
}

func (ctx *jwksContext) validateJwks(rawToken string) (*JWTClaim, error) {
	token, err := jwt.ParseWithClaims(rawToken, &JWTClaim{}, ctx.jwks.Keyfunc)
	if err != nil {
		log.Printf("Failed to parse the JWT.\nError: %s", err.Error())
		return nil, errors.New("invalid token")
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Println("The token is not valid.")
		return nil, errors.New("invalid token")
	}
	conf := ctx.config.Config.Jwt
	// Validate issuer and audience if defined
	claims := token.Claims.(*JWTClaim)
	if len(conf.Issuer) > 0 && !claims.VerifyIssuer(conf.Issuer, true) {
		log.Println("Invalid issuer ")
		return nil, errors.New("invalid issuer")
	}
	if len(conf.Audience) > 0 && !claims.VerifyAudience(conf.Audience, true) {
		log.Println("Invalid audience")
		return nil, errors.New("invalid audience")
	}
	return claims, err
}

func main() {
	syncedConfig, cancel := config.CreateConfigSync()
	ctx, err := initializeJwks(syncedConfig)
	if err != nil {
		log.Fatal("Couldn't initialize jwks")
	}
	router := gin.Default()
	router.GET("/", ctx.authenticate)

	router.Run(":8080")

	cancelFunc := *ctx.cancel
	cancelFunc()
	ctx.jwks.EndBackground()
	cancelFunc = *cancel
	cancelFunc()
}
