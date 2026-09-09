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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/markbates/goth/gothic"
	"github.com/tektoncd/hub/api/pkg/app"
	authApp "github.com/tektoncd/hub/api/pkg/auth/app"
	"github.com/tektoncd/hub/api/pkg/db/model"
	"gorm.io/gorm"
)

type service struct {
	app.Service
	api app.Config
}

type request struct {
	db            *gorm.DB
	log           *app.Logger
	defaultScopes []string
	jwtConfig     *app.JWTConfig
	provider      string
}

type AuthService struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Services struct {
	Service AuthService `json:"services"`
}

var (
	errMissingRedirectURI    = errors.New("missing redirect_uri")
	errInvalidRedirectURI    = errors.New("invalid redirect_uri")
	errInvalidRedirectScheme = errors.New("invalid redirect_uri scheme")
	errRedirectNotAllowed    = errors.New("redirect_uri is not allowed")
)

var oauthProviders = []struct {
	id, secret, name string
}{
	{"GH_CLIENT_ID", "GH_CLIENT_SECRET", "github"},
	{"BB_CLIENT_ID", "BB_CLIENT_SECRET", "bitbucket"},
	{"GL_CLIENT_ID", "GL_CLIENT_SECRET", "gitlab"},
}

type Service interface {
	AuthCallBack(res http.ResponseWriter, req *http.Request)
	HubAuthenticate(res http.ResponseWriter, req *http.Request)
}

// New returns the auth service implementation.
func New(api app.Config) Service {
	return &service{
		Service: api.Service("auth"),
		api:     api,
	}
}

func (s *service) newRequest(provider string) request {
	return request{
		db:            s.DB(context.Background()),
		log:           s.Logger(context.Background()),
		defaultScopes: s.api.Data().Default.Scopes,
		jwtConfig:     s.api.JWTConfig(),
		provider:      provider,
	}
}

func (r request) httpError(res http.ResponseWriter, err error, status int) {
	r.log.Error(err)
	http.Error(res, err.Error(), status)
}

func writeJSON(res http.ResponseWriter, log *app.Logger, v interface{}) {
	res.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(res).Encode(v); err != nil && log != nil {
		log.Error(err)
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

// Return name and status of the services
func Status(res http.ResponseWriter, req *http.Request) {
	authSvc := Services{
		AuthService{
			Name:   "auth",
			Status: "ok",
		},
	}

	var log app.Logger
	res.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(res).Encode(authSvc); err != nil {
		log.Error(err)
	}
}

// Authenticates user with the speicified git provider
// using goth and calls the AuthCallback function
func Authenticate(res http.ResponseWriter, req *http.Request) {
	if _, err := parseAllowedRedirect(req.FormValue("redirect_uri")); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	gothic.BeginAuthHandler(res, req)
}

// Once user is authenticated, store the user details in db
// and redirect to UI with the status code and auth code
func (s *service) AuthCallBack(res http.ResponseWriter, req *http.Request) {
	ui, err := parseAllowedRedirect(readConfiguredRedirectURI())
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	provider := mux.Vars(req)["provider"]
	r := s.newRequest(provider)

	ghUser, err := gothic.CompleteUserAuth(res, req)
	if err != nil {
		r.httpError(res, err, http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	status := http.StatusOK
	if err = r.insertData(ghUser, code, provider); err != nil {
		r.log.Error(err)
		status = http.StatusBadRequest
		code = ""
	}

	sendUIRedirect(res, ui, status, code, provider)
}

// Checks for auth code in the headers, validates the
// auth code and returns the jwt token for user
func (s *service) HubAuthenticate(res http.ResponseWriter, req *http.Request) {

	// Get the auth code from params
	code := req.FormValue("code")
	if code == "" {
		http.Error(res, "auth code is required", http.StatusBadRequest)
		return
	}

	r := request{
		db:            s.DB(context.Background()),
		log:           s.Logger(context.Background()),
		defaultScopes: s.api.Data().Default.Scopes,
		jwtConfig:     s.api.JWTConfig(),
	}

	var gitUser model.User
	err := r.db.Model(&model.User{}).
		Where("code = ?", req.FormValue("code")).
		First(&gitUser).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		r.httpError(res, err, http.StatusInternalServerError)
		return
	}

	// Once the user is authenticated clear the code from DB and user struct so that it can't be reused once the user logs in
	gitUser.Code = nil
	if err := r.db.Model(&model.User{}).Where("email = ?", gitUser.Email).Update("code", gitUser.Code).Error; err != nil {
		r.httpError(res, err, http.StatusInternalServerError)
		return
	}

	accountQuery := r.db.Model(&model.Account{}).Where("user_id = ?", gitUser.ID)
	if loginProvider := req.FormValue("provider"); loginProvider != "" {
		accountQuery = accountQuery.Where("provider = ?", loginProvider)
	}

	var acc model.Account
	if err := accountQuery.First(&acc).Error; err != nil {
		r.httpError(res, err, http.StatusBadRequest)
		return
	}

	scopes, err := r.userScopes(&acc)
	if err != nil {
		r.httpError(res, err, http.StatusInternalServerError)
		return
	}

	userTokens, err := r.createTokens(&gitUser, scopes, acc.Provider)
	if err != nil {
		r.httpError(res, err, http.StatusInternalServerError)
		return
	}

	writeJSON(res, r.log, userTokens)
}

// Provides a list of git provider present in auth server
func List(res http.ResponseWriter, req *http.Request) {
	providerList := make([]authApp.Provider, 0)
	for _, p := range oauthProviders {
		if os.Getenv(p.id) != "" && os.Getenv(p.secret) != "" {
			providerList = append(providerList, authApp.Provider{Name: p.name})
		}
	}

	var log app.Logger
	writeJSON(res, &log, authApp.ProviderList{Data: providerList})
}

func parseRedirectURI(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errMissingRedirectURI
	}
	if strings.ContainsAny(raw, "\r\n") {
		return nil, errInvalidRedirectURI
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errInvalidRedirectURI
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errInvalidRedirectScheme
	}
	if u.Host == "" || u.User != nil {
		return nil, errInvalidRedirectURI
	}
	return u, nil
}

func configuredRedirectURIs() []string {
	var uris []string
	if v := readConfiguredRedirectURI(); v != "" {
		uris = append(uris, v)
	}
	for _, v := range strings.Split(os.Getenv("ALLOWED_REDIRECT_URIS"), ",") {
		if s := strings.TrimSpace(v); s != "" {
			uris = append(uris, s)
		}
	}
	return uris
}

func readConfiguredRedirectURI() string {
	return strings.TrimSpace(os.Getenv("REDIRECT_URI"))
}

func normalizeRedirectHost(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

func canonicalPath(p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func pathAllowed(got, allowed string) bool {
	got = canonicalPath(got)
	allowed = strings.TrimSuffix(canonicalPath(allowed), "/")
	if allowed == "" {
		return true
	}
	return strings.TrimSuffix(got, "/") == allowed || strings.HasPrefix(got, allowed+"/")
}

func sameRedirectOrigin(candidate, allowed *url.URL) bool {
	return strings.EqualFold(candidate.Scheme, allowed.Scheme) &&
		normalizeRedirectHost(candidate) == normalizeRedirectHost(allowed)
}

func redirectURIAllowed(candidate *url.URL) bool {
	for _, raw := range configuredRedirectURIs() {
		allowed, err := parseRedirectURI(raw)
		if err != nil {
			continue
		}
		if sameRedirectOrigin(candidate, allowed) && pathAllowed(candidate.Path, allowed.Path) {
			return true
		}
	}
	return false
}

func parseAllowedRedirect(raw string) (*url.URL, error) {
	parsed, err := parseRedirectURI(raw)
	if err != nil {
		return nil, err
	}
	if !redirectURIAllowed(parsed) {
		return nil, errRedirectNotAllowed
	}
	return parsed, nil
}

func validateRedirectURI(raw string) (string, error) {
	if _, err := parseAllowedRedirect(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func redirectToUI(res http.ResponseWriter, uiURL string, status int, code, provider string) {
	u, err := parseAllowedRedirect(uiURL)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	sendUIRedirect(res, u, status, code, provider)
}

func sendUIRedirect(res http.ResponseWriter, ui *url.URL, status int, code, provider string) {
	loc := *ui
	fragment := url.Values{}
	fragment.Set("status", strconv.Itoa(status))
	if code != "" {
		fragment.Set("code", code)
	}
	if provider != "" {
		fragment.Set("provider", provider)
	}
	// Put the Hub handshake in the fragment so the auth code is not sent
	// on subsequent requests (Referer) or written to access logs / history.
	loc.Fragment = fragment.Encode()
	res.Header().Set("Location", loc.String())
	res.WriteHeader(http.StatusTemporaryRedirect)
}
