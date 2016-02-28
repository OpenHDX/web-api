package users

import (
	"encoding/json"
	"log"
	"net/http"

	// HDX imports
	"github.com/OpenHDX/web-api/modules"
	"github.com/OpenHDX/web-api/shared"
)

type Module struct{}

func (m *Module) Get(conn *shared.ConnInfo) {
	var (
		errMsg shared.ErrorMessage

		// output
		output []byte
		err    error
	)

	if nil != conn.UserInfo {
		if output, err = json.Marshal(conn.UserInfo); err != nil {
			log.Fatal(err)
		}
	} else {
		conn.Response.StatusCode = http.StatusUnauthorized
		errMsg.Message = "invalid_token"
	}

	// Check whether there is error message
	if "" != errMsg.Message {
		// There is error
		if output, err = json.Marshal(errMsg); err != nil {
			log.Fatal(err)
		}
	}

	conn.Response.Body.Write(output)
	return
}

func (m *Module) Post(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func (m *Module) Delete(conn *shared.ConnInfo) {
	conn.Response.StatusCode = http.StatusMethodNotAllowed
	return
}

func init() {
	modules.Add("users", &Module{})
}
