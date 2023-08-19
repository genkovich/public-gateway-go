package main

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8083", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("token")

	if err != nil && !errors.Is(http.ErrNoCookie, err) {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if token != nil && !validateToken(token.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if token != nil {
		r.Header.Add("Authorization", "Bearer "+token.Value)
	}

	var target string

	switch r.URL.Path {
	case "/service1":
		target = "localhost:8081"
	case "/service2":
		target = "localhost:8082"
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: target})
	proxy.ServeHTTP(w, r)
}

func validateToken(tokenString string) bool {
	secret := "secret"

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return false
	}

	expiration, err := claims.GetExpirationTime()
	if err != nil {
		return false
	}

	if time.Now().After(expiration.Time) {
		return false
	}

	return token != nil && err == nil && token.Valid
}
