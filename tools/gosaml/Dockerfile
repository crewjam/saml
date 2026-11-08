# The image holds only the binary that deploy.sh cross-compiles, with the
# inspector's WebAssembly embedded in it. Build with ./deploy.sh, not
# directly.
FROM gcr.io/distroless/static-debian12:nonroot
COPY build/gosaml /gosaml
ENV GOSAML_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/gosaml"]
