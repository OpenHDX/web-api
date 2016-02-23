// This is HDX modules control package
package modules

import (
	"bytes"
	"github.com/OpenHDX/web-api/shared"
	"net/http"
)

type ModuleRequester interface {
	Get(http.ResponseWriter, *bytes.Buffer, *http.Request, *shared.ConnInfo)
	Post(http.ResponseWriter, *bytes.Buffer, *http.Request, *shared.ConnInfo)
	Delete(http.ResponseWriter, *bytes.Buffer, *http.Request, *shared.ConnInfo)
}

var modules map[string]ModuleRequester

func Add(name string, module ModuleRequester) {
	modules[name] = module
}

func IsExist(name string) bool {
	for key := range modules {
		if name == key {
			return true
		}
	}
	return false
}

func Get(module string, w http.ResponseWriter, o *bytes.Buffer, r *http.Request, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Get(w, o, r, conn)
	}
}

func Post(module string, w http.ResponseWriter, o *bytes.Buffer, r *http.Request, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Post(w, o, r, conn)
	}
}

func Delete(module string, w http.ResponseWriter, o *bytes.Buffer, r *http.Request, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Delete(w, o, r, conn)
	}
}

func init() {
	modules = make(map[string]ModuleRequester)
}
