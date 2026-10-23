# Base images are pinned by digest: the verifier holds the certificate authority of every
# monitored host.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/cpibia/tripwatch/internal/buildinfo.Version=${VERSION} -X github.com/cpibia/tripwatch/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/tripwatch-verifier ./cmd/tripwatch-verifier \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/tripwatch-verifier /tripwatch-verifier
# A new named volume takes the owner of this directory, so the non-root user can write to it.
COPY --from=build --chown=65532:65532 /out/data /data
ENV TRIPWATCH_DATA=/data
USER 65532:65532
EXPOSE 8443 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/tripwatch-verifier", "healthcheck"]
ENTRYPOINT ["/tripwatch-verifier"]
CMD ["serve"]
