//go:build js && wasm

// Command wasm is the SAML inspector compiled to WebAssembly. It runs in
// the browser, so that the messages people paste into the inspector page
// are decoded there and never reach the server.
//
// It defines one global function, samlInspect(input string) string, which
// returns the JSON of an inspect.Result, and then dispatches a
// "saml-inspect-ready" event on window.
package main

import (
	"encoding/json"
	"syscall/js"
	"time"

	"github.com/crewjam/saml/tools/gosaml/inspect"
)

func main() {
	js.Global().Set("samlInspect", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return `{"error":"samlInspect takes one string"}`
		}
		b, err := json.Marshal(inspect.Parse(args[0].String(), time.Now()))
		if err != nil {
			return `{"error":"cannot encode the result"}`
		}
		return string(b)
	}))
	js.Global().Set("samlInspectReady", true)
	js.Global().Call("dispatchEvent", js.Global().Get("Event").New("saml-inspect-ready"))
	select {}
}
