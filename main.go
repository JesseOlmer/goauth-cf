package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/nu7hatch/gouuid"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"./cloud-functions-go/nodego"
)

var (
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("OAuthRedirectURL"),
		ClientID:     os.Getenv("OAuthClientID"),
		ClientSecret: os.Getenv("OAuthSecret"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint: google.Endpoint,
	}
)

func init() {
	nodego.OverrideLogger()
}

func main() {
	flag.Parse()

	http.HandleFunc("/execute/", nodego.WithLoggerFunc(handleDefault))

	http.HandleFunc("/execute/GoogleLogin", nodego.WithLoggerFunc(handleGoogleLogin))
	http.HandleFunc("/execute/GoogleCallback", nodego.WithLoggerFunc(handleGoogleCallback))

	log.Printf("OAuth Config. Client: %s, Secret: %s", googleOauthConfig.ClientID, googleOauthConfig.ClientSecret)

	nodego.TakeOver()
}

func handleDefault(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Native Go Request: %s\n", r.URL.String())
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	state, _ := uuid.NewV4()
	cookie := http.Cookie{Name: "OAuthState", Value: state.String()}
	http.SetCookie(w, &cookie)

	url := googleOauthConfig.AuthCodeURL(state.String())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state matches
	state := r.FormValue("state")
	cookie, _ := r.Cookie("OAuthState")
	if state != cookie.Value {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", r.Context().Value("oauthState"), state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Get Token
	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Get profile info and print it out
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	fmt.Fprintf(w, "Content: %s\n", contents)
}
