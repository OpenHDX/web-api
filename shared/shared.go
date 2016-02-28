package shared

import (
	"bytes"
	"database/sql"
	"net/http"
)

const (
	// Random data for fingerprint and verification code
	SECRET_KEY   = "SECRET_KEY_GO_HERE"
	VERIFIER_KEY = "VERIFIER_SECRET_KEY_GO_HERE"

	// Auth verifier token expire time = 2 minutes
	AUTH_VERIFIER_EXPIRE_TIME = 2 * 60

	// Session expire time = 15 minutes
	SESSION_EXPIRE_TIME = 15 * 60

	// Session renew time = 3 minutes
	SESSION_RENEW_TIME = 3 * 60
)

// Global database connection
var DB *sql.DB

// Business info store
type BusinessInfo struct {
	Id       int
	Country  string
	Language string
}

// Business data store
var BusinessData = make(map[string]*BusinessInfo)

// User token
type UserInfo struct {
	UUID     string `json:"sub"`
	Name     string `json:"name"`
	Language string `json:"userLanguage"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

type Response struct {
	StatusCode int
	Header     map[string]string
	Body       bytes.Buffer
}

// Connection info store
type ConnInfo struct {
	Domain       string
	Request      *http.Request
	RequestTime  int64
	Fingerprint  string
	BusinessInfo *BusinessInfo
	UserInfo     *UserInfo
	Response
}

type ErrorMessage struct {
	Message  string `json:"error"`
	Delay    int64  `json:"delay,omitempty"`
	Verifier string `json:"verifier,omitempty"`
}
