// This is HDX modules control package
package modules

import "github.com/OpenHDX/web-api/shared"

type ModuleRequester interface {
	Get(*shared.ConnInfo)
	Post(*shared.ConnInfo)
	Delete(*shared.ConnInfo)
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

func Get(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Get(conn)
	}
}

func Post(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Post(conn)
	}
}

func Delete(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Delete(conn)
	}
}

func init() {
	modules = make(map[string]ModuleRequester)
}
