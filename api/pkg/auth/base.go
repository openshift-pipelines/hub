// Copyright © 2021 The Tekton Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/tektoncd/hub/api/pkg/app"
	"github.com/tektoncd/hub/api/pkg/auth/provider"
	auth "github.com/tektoncd/hub/api/pkg/auth/service"
)

// generateRandomKey return a random generated key
func generateRandomKey(length int) (string, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// sessionCookieStore configures gothic's CookieStore for the OAuth redirect.
// Hub API and UI are often HTTP even in production, so Secure follows AUTH_BASE_URL
// (https only). SameSite=Lax is required on HTTP: gorilla/sessions defaults to
// SameSite=None, which browsers drop unless the cookie is also Secure.
func sessionCookieStore(key []byte, authBaseURL string) *sessions.CookieStore {
	store := sessions.NewCookieStore(key)
	store.MaxAge(86400 * 30) // 30 days
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = strings.HasPrefix(strings.ToLower(strings.TrimSpace(authBaseURL)), "https://")
	store.Options.SameSite = http.SameSiteLaxMode
	return store
}

// Auth Provider provides routes for authentication
// and also defines git providers using goth
func AuthProvider(r *mux.Router, api app.Config) {

	key, err := generateRandomKey(32)
	if err != nil {
		panic(err)
	}

	var AUTH_BASE_URL = os.Getenv("AUTH_BASE_URL")
	gothic.Store = sessionCookieStore([]byte(key), AUTH_BASE_URL)

	var AUTH_URL = strings.TrimSuffix(AUTH_BASE_URL, "/") + "/auth/%s/callback"

	githubAuth := provider.GithubProvider(AUTH_URL)
	gitlabAuth := provider.GitlabProvider(AUTH_URL)
	bitbucketAuth := provider.BitbucketProvider(AUTH_URL)

	goth.UseProviders(
		github.NewCustomisedURL(
			githubAuth.ClientId,
			githubAuth.ClientSecret,
			githubAuth.CallbackUrl,
			githubAuth.AuthUrl,
			githubAuth.TokenUrl,
			githubAuth.ProfileUrl,
			githubAuth.EmailUrl,
			"user:email"),

		gitlab.NewCustomisedURL(
			gitlabAuth.ClientId,
			gitlabAuth.ClientSecret,
			gitlabAuth.CallbackUrl,
			gitlabAuth.AuthUrl,
			gitlabAuth.TokenUrl,
			gitlabAuth.ProfileUrl,
			"read_user",
		),

		bitbucket.New(
			bitbucketAuth.ClientId,
			bitbucketAuth.ClientSecret,
			bitbucketAuth.CallbackUrl,
			"email",
		),
	)

	authSvc := auth.New(api)

	// Return name and status of the services
	r.HandleFunc("/", auth.Status)

	s := r.PathPrefix("/auth").Subrouter()

	// Provides a list of git provider present in auth server
	s.HandleFunc("/providers", auth.List)

	// Checks for auth code, validates it and returns users jwt token
	s.HandleFunc("/login", authSvc.HubAuthenticate).Methods(http.MethodPost)

	// Redirects to UI with the status code and auth code
	s.HandleFunc("/{provider}/callback", authSvc.AuthCallBack)

	// Authenticates user with the speicified git provider
	s.HandleFunc("/{provider}", auth.Authenticate)
}
