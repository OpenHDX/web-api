package sessions

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"strconv"

	"database/sql"

	// HDX imports
	"github.com/OpenHDX/web-api/modules"
	"github.com/OpenHDX/web-api/shared"
	"github.com/OpenHDX/web-api/token"
)

type AuthMsg struct {
	Token    string `json:"accessToken"`
	Verifier string `json:"verifier,omitempty"`
}

type Module struct{}

func (m *Module) Get(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func (m *Module) Post(conn *shared.ConnInfo) {
	var (
		// POST values
		username string = conn.Request.PostFormValue("username")
		UUID     string = conn.Request.PostFormValue("sub")
		password string = conn.Request.PostFormValue("password")

		// User data
		userData     shared.UserInfo
		userToken    []byte
		userPassword string

		// SQL
		SQLCond  string
		SQLValue string

		// To store new verifier token
		newVerifier string
		errMsg      shared.ErrorMessage

		// output
		output []byte
		err    error
	)

	// Generate new verifier token to be able to send it
	newVerifier = token.New(conn.Fingerprint, conn.Domain, strconv.FormatInt(conn.RequestTime, 10), shared.VERIFIER_KEY)

	// Check the verifier and get the issued time
	if msg := token.Get(conn.Fingerprint, conn.Domain, conn.Request.Header.Get("Verifier"), shared.VERIFIER_KEY); "" != msg {
		// Parse verifier message to issued time
		if issuedTime, err := strconv.ParseInt(msg, 10, 64); err == nil {
			// Check whether issued time valid and not expired
			if issuedTime <= conn.RequestTime && issuedTime+shared.AUTH_VERIFIER_EXPIRE_TIME > conn.RequestTime {
				// Set the appropiate SQL condition
				if "" != username {
					SQLCond = "username = ?"
					SQLValue = username
				} else if "" != UUID {
					SQLCond = "id = ?"
					SQLValue = UUID
				}

				// Get user data
				err = shared.DB.QueryRow("SELECT id, password, displayName, mainLanguage FROM user WHERE "+SQLCond+" AND deleted = '0' LIMIT 1", SQLValue).Scan(&userData.UUID, &userPassword, &userData.Name, &userData.Language)
				if err == sql.ErrNoRows {
					// User/session did not exist
					conn.Response.StatusCode = http.StatusUnauthorized
					errMsg.Message = "invalid_grant"
				} else if err == nil {
					// User exist, check password
					/*newPassword, _ := bcrypt.GenerateFromPassword([]byte("schina"), 10)
					  db.Exec("UPDATE user SET password = ? WHERE " + SQLCond + " AND deleted = '0' LIMIT 1", string(newPassword), SQLValue)*/
					if nil == bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(password)) {
						// Password correct, generate user data feedback
						userData.UUID = username
						userData.Role = "admin"
						userData.Exp = conn.RequestTime + shared.SESSION_EXPIRE_TIME
						if userToken, err = json.Marshal(userData); err != nil {
							log.Fatal(err)
						}

						// Generate auth token
						if output, err = json.Marshal(AuthMsg{token.New(conn.Fingerprint, conn.Domain, string(userToken), shared.SECRET_KEY), newVerifier}); err != nil {
							log.Fatal(err)
						}
					} else {
						// Password incorrect
						conn.Response.StatusCode = http.StatusUnauthorized
						errMsg.Message = "invalid_grant"
						// log.Print(bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(password)))
					}
				} else {
					// Something happened
					log.Fatal(err)
				}
			} else {
				// Issued time is either before server time or expired
				if issuedTime > conn.RequestTime {
					conn.Response.StatusCode = http.StatusTooManyRequests
					errMsg.Message = "invalid_request"
					errMsg.Delay = issuedTime - conn.RequestTime
				} else {
					conn.Response.StatusCode = http.StatusUnauthorized
					errMsg.Message = "invalid_token"
				}
			}
		} else {
			log.Fatal(err)
		}
	} else {
		// Verifier error
		conn.Response.StatusCode = http.StatusUnauthorized
		errMsg.Message = "invalid_token"
	}

	// Check whether there is error message
	if "" != errMsg.Message {
		errMsg.Verifier = newVerifier
		if output, err = json.Marshal(errMsg); err != nil {
			log.Fatal(err)
		}
	}

	conn.Response.Body.Write(output)
	return
}

func (m *Module) Put(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func (m *Module) Patch(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func (m *Module) Delete(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func init() {
	modules.Add("sessions", &Module{})
}
