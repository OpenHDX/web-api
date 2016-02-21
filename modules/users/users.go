package users

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	// HDX imports
	"github.com/OpenHDX/web-api/modules"
	"github.com/OpenHDX/web-api/shared"
)

type Module struct{}

func (m *Module) Get(w http.ResponseWriter, o *bytes.Buffer, _ *http.Request, conn *shared.ConnInfo) {
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
		errMsg.StatusCode = http.StatusUnauthorized
		errMsg.Message = "invalid_token"
	}

	// Check whether there is error message
	if "" != errMsg.Message {
		// There is error
		w.WriteHeader(errMsg.StatusCode)

		if output, err = json.Marshal(errMsg); err != nil {
			log.Fatal(err)
		}
	}

	o.Write(output)
	return
}

func (m *Module) Post(w http.ResponseWriter, _ *bytes.Buffer, _ *http.Request, _ *shared.ConnInfo) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	return
}

func (m *Module) Delete(w http.ResponseWriter, _ *bytes.Buffer, _ *http.Request, _ *shared.ConnInfo) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	return
}

func init() {
	modules.Add("users", &Module{})
}
