#!/usr/bin/env bash
# Builds gosaml and deploys it to Fly.io.
#
#   ./deploy.sh            build for linux/amd64 and deploy to Fly.io
#   ./deploy.sh build      build for this machine, into build/gosaml
#   ./deploy.sh run        build for this machine and run it at http://localhost:8080
#
# Extra arguments after "deploy" are passed to `fly deploy`.
#
# It does not run the tests: CI does, and the GitHub Actions workflow runs
# this only after they pass. Run `go vet ./... && go test ./...` yourself
# before deploying by hand.
#
# The inspector is cross-compiled to WebAssembly (web/static/parser.wasm),
# with the wasm_exec.js of the same Go toolchain, and both are embedded in
# the server binary. The binary is built here, not in Docker, so the image
# is just the binary, and the build uses the library from this checkout
# (see the replace directive in go.mod).
set -euo pipefail
cd "$(dirname "$0")"

cmd="${1:-deploy}"
[ $# -gt 0 ] && shift

build_wasm() {
	echo "==> building the inspector (js/wasm)"
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/static/parser.wasm ./wasm
	# The JavaScript glue must come from the same Go version as the
	# WebAssembly. It moved to lib/wasm in Go 1.24.
	local goroot
	goroot="$(go env GOROOT)"
	if [ -f "$goroot/lib/wasm/wasm_exec.js" ]; then
		cp "$goroot/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
	else
		cp "$goroot/misc/wasm/wasm_exec.js" web/static/wasm_exec.js
	fi
	ls -lh web/static/parser.wasm | awk '{print "    parser.wasm: " $5}'
}

build_server() {
	echo "==> building the server ($1/$2)"
	# The footer shows this version; the commit hash comes from the VCS
	# information that go build stamps into the binary.
	local version
	version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
	echo "    version: $version"
	mkdir -p build
	GOOS="$1" GOARCH="$2" CGO_ENABLED=0 go build -trimpath \
		-ldflags="-s -w -X github.com/crewjam/saml/tools/gosaml/server.Version=$version" \
		-o build/gosaml .
}

case "$cmd" in
build)
	build_wasm
	build_server "$(go env GOOS)" "$(go env GOARCH)"
	;;
run)
	build_wasm
	build_server "$(go env GOOS)" "$(go env GOARCH)"
	exec ./build/gosaml
	;;
deploy)
	fly="$(command -v fly || command -v flyctl || true)"
	if [ -z "$fly" ]; then
		echo "flyctl is not installed: https://fly.io/docs/flyctl/install/" >&2
		exit 1
	fi
	build_wasm
	build_server linux amd64
	echo "==> deploying"
	# One machine only: the SQLite database is on that machine's volume,
	# so a second machine would have different state. The database
	# survives the deploy; instances still expire after GOSAML_TTL.
	"$fly" deploy --ha=false "$@"
	;;
*)
	echo "usage: $0 [deploy|build|run] [fly deploy flags...]" >&2
	exit 2
	;;
esac
