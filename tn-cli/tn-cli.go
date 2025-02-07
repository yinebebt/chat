// Go implementation of tn-cli.
package main

import (
	"github.com/tinode/chat/server/logs"
	"github.com/tinode/chat/tn-cli/cmd"
	"os"
)

func main() {
	logs.Init(os.Stderr, "stdFlags")
	cmd.Execute()
}
