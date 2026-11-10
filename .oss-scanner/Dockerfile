# Build image for the oss-scanner (https://github.com/anthropics/oss-scanner).
# crewjam/saml: a pure-Go SAML 2.0 library (SP and IdP). The scanner builds this with the
# repository checkout as the build context.
FROM golang:1.27-bookworm

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module (the root module and the separate tools/gosamldev module) while the network is up.
ENV GOTOOLCHAIN=local
RUN go mod download all && (cd tools/gosamldev && go mod download all)

# Build everything so the image works and the build cache is warm.
RUN go build ./... && (go vet ./... || echo "WARNING: go vet reported problems")
RUN cd tools/gosamldev && go build ./... && GOOS=js GOARCH=wasm go build -o /dev/null ./wasm

# Compile and run the tests once so the test cache is warm offline; don't fail the build on a test failure.
RUN (go test -count=1 ./... || echo "WARNING: root module tests reported failures") \
    && (cd tools/gosamldev && go test -count=1 ./... || echo "WARNING: gosamldev tests reported failures")

# Race-instrumented build of the packages, for reproducing concurrency findings offline.
RUN go test -race -run XXX_NONE ./... >/dev/null 2>&1 || true
