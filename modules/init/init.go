package init

import (
	"encoding/json"
	"net/http"

	"strconv"

	// HDX imports
	"github.com/OpenHDX/web-api/modules"
	"github.com/OpenHDX/web-api/shared"
	"github.com/OpenHDX/web-api/token"
)

type Init struct {
	AppCountry  string `json:"appCountry"`
	AppLanguage string `json:"appLanguage"`
	ServerTime  int64  `json:"serverTime"`
	Verifier    string `json:"verifier,omitempty"`
}

type Module struct{}

func (m *Module) Get(conn *shared.ConnInfo) {
	init, _ := json.Marshal(Init{
		conn.BusinessInfo.Country,
		conn.BusinessInfo.Language,
		conn.RequestTime,
		token.New(conn.Fingerprint, conn.Domain, strconv.FormatInt(conn.RequestTime, 10), shared.VERIFIER_KEY)})
	conn.Response.Body.Write(init)
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
	modules.Add("init", &Module{})
}
