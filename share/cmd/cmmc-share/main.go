// Command cmmc-share is the DMZ-facing share daemon. See the
// daemon package godoc for the full design.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/filebrowser/filebrowser/v2/share/daemon"
)

// Version is set by -ldflags at build time; helpful in audit logs
// and the /healthz-style plumbing operators wire up later.
var Version = "dev"

func main() {
	cfg, printVersion, err := daemon.ParseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "cmmc-share: %v\n", err)
		os.Exit(2)
	}
	if printVersion {
		fmt.Println("cmmc-share", Version)
		return
	}
	if err := daemon.Run(context.Background(), cfg); err != nil {
		log.Fatalf("cmmc-share: %v", err)
	}
}
