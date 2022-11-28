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
	"reflect"
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
	Roles   []string
	Subject string
	Claims  jwt.MapClaims
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
	roles := claims.Roles
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
	token, err := jwt.ParseWithClaims(rawToken, jwt.MapClaims{}, ctx.jwks.Keyfunc)
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
	claims := token.Claims.(jwt.MapClaims)
	if len(conf.Issuer) > 0 && !claims.VerifyIssuer(conf.Issuer, true) {
		log.Println("Invalid issuer ")
		return nil, errors.New("invalid issuer")
	}
	if len(conf.Audience) > 0 && !claims.VerifyAudience(conf.Audience, true) {
		log.Println("Invalid audience")
		return nil, errors.New("invalid audience")
	}
	var roles []string
	// Parse roles from scopes
	switch v := claims["scope"].(type) {
	case string:
		roles = append(strings.Split(v, " "), v)
		break
	case []string:
		roles = v
		break
	default:
		log.Println("Unknown scope claim type " + reflect.TypeOf(v).String())
	}
	if conf.TrimPrefixInScopes {
		// This is used to trim prefix ending in forward slash from scopes. This functionality is related to aws cognito when using client credentials.
		// Client credentials cannot be assigned a "cognito_groups" claim the same way as the users can have and they will also contain a prefix
		// We want to allow access control to use same roles for logged users and client credentials so we trim prefix from scopes
		for i, role := range roles {
			var index = strings.Index(role, "/")
			if index != -1 {
				roles[i] = role[index+1:]
			}
		}
	}
	// Parse roles from custom claim if defined
	if len(conf.RoleClaim) > 0 {
		// Custom claim for roles present
		claimsMap := token.Claims.(jwt.MapClaims)
		roleClaim, ok := claimsMap[conf.RoleClaim]
		if ok {
			switch v := roleClaim.(type) {
			case string:
				roles = append(roles, v)
				break
			case []string:
				roles = append(roles, v...)
				break
			case []interface{}:
				for _, a := range v {
					vs, ok := a.(string)
					if ok {
						roles = append(roles, vs)
					}
				}
			default:
				log.Println("Unknown role claim type " + reflect.TypeOf(roleClaim).String())
			}
		}
	}
	jwtClaim := &JWTClaim{Roles: roles, Claims: claims}
	// Parse subject field from token
	sub, ok := claims["sub"]
	if !ok {
		log.Println("No subject present in the token")
		return nil, errors.New("no subject in token")
	}
	if subject, ok2 := sub.(string); ok2 {
		jwtClaim.Subject = subject
	} else {
		log.Println("Token subject was of invalid type")
		return nil, errors.New("token subject was of invalid type")
	}
	return jwtClaim, nil
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
