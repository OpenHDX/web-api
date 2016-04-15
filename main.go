// The main file for HDX REST API server
package main

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	// Encryption
	"crypto/sha256"

	// Encoding
	"encoding/base64"
	"encoding/json"

	// MySQL
	"database/sql"
	_ "github.com/go-sql-driver/mysql"

	// HDX shared
	"github.com/OpenHDX/web-api/shared"

	// HDX token
	"github.com/OpenHDX/web-api/token"

	// HDX modules
	"github.com/OpenHDX/web-api/modules"
	_ "github.com/OpenHDX/web-api/modules/init"
	_ "github.com/OpenHDX/web-api/modules/sessions"
	_ "github.com/OpenHDX/web-api/modules/users"
)

// HDX multiplexer
type HDXMux struct{}

func getBusinessData(domain string) int {
	var (
		isBusinessDataCache bool  = false
		err                 error // Error handler
	)

	// Check whether data exist in business data cache
	for key := range shared.BusinessData {
		if domain == key {
			isBusinessDataCache = true
		}
	}

	if !isBusinessDataCache {
		// No previous cache, initialize new cache
		shared.BusinessData[domain] = &shared.BusinessInfo{}

		// Get the business data
		err = shared.DB.QueryRow("SELECT id, country, mainLanguage FROM business WHERE path = ? LIMIT 1", domain).Scan(
			&shared.BusinessData[domain].Id,
			&shared.BusinessData[domain].Country,
			&shared.BusinessData[domain].Language)

		switch {
		// In case that the business is not registered
		case err == sql.ErrNoRows:
			// Return 403 invalid_client
			return http.StatusNotFound
		// In case any other error
		case err != nil:
			log.Fatal(err)
			return http.StatusInternalServerError
		}
	} else {
		// In case that the business is not registered
		if 0 == shared.BusinessData[domain].Id {
			// Return 403 invalid_client
			return http.StatusNotFound
		}
	}

	return http.StatusOK
}

func checkAuthorization(ah string, currentConn *shared.ConnInfo) int {
	var tokenMsg shared.UserInfo // Token data

	// Get the token on the "Authorization" header if exist
	if "" != ah {
		// Check whether the "Authorization" header has a valid format
		// The header should be a HDX token
		if 4 < len(ah) && "HDX " == strings.ToUpper(ah[0:4]) {
			// Try to get the message and cert the token
			if raw := token.Get(currentConn.Fingerprint, currentConn.Domain, ah[4:], shared.SECRET_KEY); "" != raw {
				// Decifrate the JSON message and check whether the token expired
				if err := json.Unmarshal([]byte(raw), &tokenMsg); err != nil || currentConn.RequestTime > tokenMsg.Exp {
					// Token expired, return 401 unauthorized
					return http.StatusUnauthorized
				}

				// Everything is ok
				currentConn.UserInfo = &tokenMsg
				return http.StatusOK
			} else {
				// 'Authorization' header invalid, return 401 unauthorized
				return http.StatusUnauthorized
			}
		} else {
			// 'Authorization' header invalid, return 401 unauthorized
			return http.StatusUnauthorized
		}
	}

	return http.StatusOK
}

// HDX default router
func (m *HDXMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		// This store connection data to be shared between modules
		currentConn = shared.ConnInfo{
			// Get the requested business domain to wildcard domain detection
			Domain: strings.TrimSuffix(r.Host, DOMAIN_SUFFIX),

			// Attach the request
			Request: r,

			// Get the request time
			RequestTime: time.Now().Unix(),
		}

		// Get the requested page
		path string = strings.Trim(strings.TrimPrefix(r.RequestURI, PATH_PREFIX), "/")
		page string = strings.SplitN(path, "/", 2)[0]

		// Client fingerprint encripter
		fingerprintCrypto = sha256.New()
	)

	// Generate client fingerprint using IP address, user agent and domain
	// The value is base64 encoded
	io.WriteString(fingerprintCrypto, r.Header.Get("RemoteAddr")+r.UserAgent()+currentConn.Domain)
	currentConn.Fingerprint = base64.RawURLEncoding.EncodeToString(fingerprintCrypto.Sum(nil))

	// Get the business data and check whether business data is OK
	currentConn.Response.StatusCode = getBusinessData(currentConn.Domain)
	if http.StatusOK == currentConn.Response.StatusCode {
		// Check "Authorization" header
		currentConn.Response.StatusCode = checkAuthorization(r.Header.Get("Authorization"), &currentConn)
		if http.StatusOK == currentConn.Response.StatusCode {
			// Check whether page exist if there authorized
			if modules.IsExist(page) {
				// Pass business info to current connection data
				currentConn.BusinessInfo = shared.BusinessData[currentConn.Domain]

				switch r.Method {
				case http.MethodGet:
					modules.Get(page, &currentConn)
				case http.MethodPost:
					modules.Post(page, &currentConn)
				case http.MethodPut:
					modules.Put(page, &currentConn)
				case http.MethodPatch:
					modules.Patch(page, &currentConn)
				case http.MethodDelete:
					modules.Delete(page, &currentConn)
				default:
					currentConn.Response.StatusCode = http.StatusMethodNotAllowed
				}
			} else {
				currentConn.Response.StatusCode = http.StatusNotFound
			}
		}
	}

	// Set headers to match JSON response and avoid being cached by browser
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")

	// Send status code
	if 0 < currentConn.Response.StatusCode {
		w.WriteHeader(currentConn.Response.StatusCode)
	}

	// 5 characters to avoid CSRF attack
	if http.StatusNoContent != currentConn.Response.StatusCode &&
		http.StatusNotFound != currentConn.Response.StatusCode {
		io.WriteString(w, ")]}'\n")
		currentConn.Response.Body.WriteTo(w)
	}

	return
}

func main() {
	log.Print("Starting HDX API Server...")

	var err error

	// Get MySQL database handler
	shared.DB, err = sql.Open("mysql", SQL_DSN)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer shared.DB.Close()

	// Validate DSN data by connecting to the MySQL server
	log.Print("Connecting to MySQL server...")
	err = shared.DB.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Initialize web server
	log.Print("Initializing web server...")
	var mux = &HDXMux{}
	err = http.ListenAndServe(":9090", mux)
	if err != nil {
		log.Fatal(err)
	}
}
