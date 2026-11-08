package server

import (
	"runtime/debug"
	"sync"
)

// Version is the version of this build, shown in the footer. deploy.sh
// sets it with -ldflags "-X ...server.Version=$(git describe ...)".
var Version = ""

// Build says what this binary was built from.
type Build struct {
	Version  string // from Version; "dev" when it was not set
	Commit   string // the full commit hash, or "" when not known
	Modified bool   // the working tree had uncommitted changes
}

// Short is the commit hash abbreviated to 7 characters.
func (b Build) Short() string {
	if len(b.Commit) > 7 {
		return b.Commit[:7]
	}
	return b.Commit
}

// buildInfo is read once: the commit comes from the VCS information the
// go command stamps into binaries built inside a git checkout.
var buildInfo = sync.OnceValue(func() Build {
	b := Build{Version: Version}
	if b.Version == "" {
		b.Version = "dev"
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				b.Commit = s.Value
			case "vcs.modified":
				b.Modified = s.Value == "true"
			}
		}
	}
	return b
})
