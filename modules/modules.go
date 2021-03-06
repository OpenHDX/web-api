// This is HDX modules control package
package modules

import "github.com/OpenHDX/web-api/shared"

type Requester interface {
	Get(*shared.ConnInfo)
	Post(*shared.ConnInfo)
	Put(*shared.ConnInfo)
	Patch(*shared.ConnInfo)
	Delete(*shared.ConnInfo)
}

var modules map[string]Requester

func init() {
	modules = make(map[string]Requester)
}

// Register makes a HDX module available to be called with HTTP methods. This
// is intended to be called from the init function in packages that implement
// the module.
func Register(name string, module Requester) {
	modules[name] = module
}

// IsExist check whether a module exist
func IsExist(name string) bool {
	if _, dup := modules[name]; dup {
		return true
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

func Put(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Put(conn)
	}
}

func Patch(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Patch(conn)
	}
}

func Delete(module string, conn *shared.ConnInfo) {
	if IsExist(module) {
		modules[module].Delete(conn)
	}
}
