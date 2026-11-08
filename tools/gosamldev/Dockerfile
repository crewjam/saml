# The image holds only the binary that deploy.sh cross-compiles, with the
# inspector's WebAssembly embedded in it. Build with ./deploy.sh, not
# directly.
#
# Not the :nonroot variant: Fly mounts the database volume owned by root,
# and there is no shell in this image to change that.
FROM gcr.io/distroless/static-debian12
COPY build/gosamldev /gosamldev
ENV GOSAML_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/gosamldev"]
