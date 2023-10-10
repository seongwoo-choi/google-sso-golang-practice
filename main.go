package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	oauthGoogleUrlAPI  = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	oauthRedirectUrl   = "http://localhost:3000/auth/google/callback"
	userInfoEmailUrl   = "https://www.googleapis.com/auth/userinfo.email"
	userInfoProfileUrl = "https://www.googleapis.com/auth/userinfo.profile"
)

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  oauthRedirectUrl,
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_SECRET_KEY"),
	Scopes:       []string{userInfoEmailUrl, userInfoProfileUrl},
	Endpoint:     google.Endpoint,
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateStateOauthCookie(w)
	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	expiration := time.Now().Add(1 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := &http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, cookie)
	return state
}

type UserInfo struct {
	ID          string `json:"id"`
	EMAIL       string `json:"email"`
	NAME        string `json:"name"`
	GivenName   string `json:"given_name"`
	FamilyName  string `json:"family_name"`
	PICTURE     string `json:"picture"`
	LOCALE      string `json:"locale"`
	AccessToken string `json:"access_token"`
	HD          string `json:"hd"`
}

func googleAuthCallback(w http.ResponseWriter, r *http.Request) {
	oauthstate, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthstate.Value {
		log.Printf("invalid google oauth state cookie:%s state:%s\n", oauthstate.Value, r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Failed to Exchange %s\n\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	resp, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		log.Printf("Failed to Get UserInfo %s\n\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to Read UserInfo %s\n\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	user := UserInfo{}
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	user.AccessToken = token.AccessToken

	if user.HD != "musinsa.com" {
		log.Printf("Failed to Login %s\n\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	//fmt.Fprint(w, user)
	jsonResponse, err := json.Marshal(user)
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// JSON 응답 헤더 설정
	w.Header().Set("Content-Type", "application/json")

	// JSON 응답 보내기
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/auth/google/login", googleLoginHandler)
	r.HandleFunc("/auth/google/callback", googleAuthCallback)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "public/index.html")
	})
	r.Use(loggingMiddleware)

	log.Fatal(http.ListenAndServe(":3000", r))
}
