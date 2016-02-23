// The main file for HDX REST API server
package main

import (
	"bytes"
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

// HDX default router
func (m *HDXMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var currentConn = shared.ConnInfo{
		// Get the requested business domain to wildcard domain detection
		Domain: strings.TrimSuffix(r.Host, DOMAIN_SUFFIX),

		// Get the request time
		RequestTime: time.Now().Unix(),
	}

	var (
		// Output
		output bytes.Buffer

		// Get the requested page
		path string = strings.Trim(strings.TrimPrefix(r.RequestURI, PATH_PREFIX), "/")
		page string = strings.SplitN(path, "/", 2)[0]

		// Token data
		tokenMsg shared.UserInfo

		// Error handler
		err error
	)

	// Set headers to match JSON response and avoid being cached by browser
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")

	// Check whether data exist in business data cache
	var isBusinessDataCache bool = false
	for key := range shared.BusinessData {
		if currentConn.Domain == key {
			isBusinessDataCache = true
		}
	}

	if !isBusinessDataCache {
		// No previous cache, initialize new cache
		shared.BusinessData[currentConn.Domain] = &shared.BusinessInfo{}

		// Get the business data
		err = shared.DB.QueryRow("SELECT id, country, mainLanguage FROM business WHERE path = ? LIMIT 1", currentConn.Domain).Scan(
			&shared.BusinessData[currentConn.Domain].Id,
			&shared.BusinessData[currentConn.Domain].Country,
			&shared.BusinessData[currentConn.Domain].Language)
		switch {
		// In case that the business is not registered
		case err == sql.ErrNoRows:
			// Return 403 invalid_client
			w.WriteHeader(http.StatusNotFound)
			return
		// In case any other error
		case err != nil:
			log.Fatal(err)
		}
	} else {
		// In case that the business is not registered
		if 0 == shared.BusinessData[currentConn.Domain].Id {
			// Return 403 invalid_client
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	// Generate client fingerprint using IP address, user agent and domain
	// The value is base64 encoded
	fingerprintCrypto := sha256.New()
	io.WriteString(fingerprintCrypto, r.Header.Get("RemoteAddr")+r.UserAgent()+currentConn.Domain)
	currentConn.Fingerprint = base64.RawURLEncoding.EncodeToString(fingerprintCrypto.Sum(nil))

	// Get the token on the "Authorization" header if exist
	if ah := r.Header.Get("Authorization"); "" != ah {
		// Check whether the "Authorization" header has a valid format
		// The header should be a HDX token
		if 4 < len(ah) && "HDX " == strings.ToUpper(ah[0:4]) {
			// Try to get the message and cert the token
			if raw := token.Get(currentConn.Fingerprint, currentConn.Domain, ah[4:], shared.SECRET_KEY); "" != raw {
				// Decifrate the JSON message and check whether the token expired
				if err = json.Unmarshal([]byte(raw), &tokenMsg); err != nil || currentConn.RequestTime > tokenMsg.Exp {
					// Token expired, return 401 unauthorized
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				currentConn.UserInfo = &tokenMsg
			} else {
				// 'Authorization' header invalid, return 401 unauthorized
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			// 'Authorization' header invalid, return 401 unauthorized
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Go here if 'Authorization' header is valid or not exist

	// Check whether page exist
	if modules.IsExist(page) {
		// Pass business info to current connection data
		currentConn.BusinessInfo = shared.BusinessData[currentConn.Domain]

		switch r.Method {
		case http.MethodGet:
			modules.Get(page, w, &output, r, &currentConn)
		case http.MethodPost:
			modules.Post(page, w, &output, r, &currentConn)
		case http.MethodDelete:
			modules.Delete(page, w, &output, r, &currentConn)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// 5 characters to avoid CSRF attack
	io.WriteString(w, ")]}'\n")
	output.WriteTo(w)
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
