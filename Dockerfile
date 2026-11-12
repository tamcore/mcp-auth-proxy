# Runtime-only image. The binary is built outside this Dockerfile (GoReleaser or
# `go build`) and copied in, so no toolchain, shell, or package manager ships in
# the final image. The base is pinned by the multi-arch *index* digest.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETPLATFORM

LABEL org.opencontainers.image.title="mcp-auth-proxy" \
      org.opencontainers.image.description="Personal MCP auth proxy with one-time-code tool gates" \
      org.opencontainers.image.source="https://github.com/tamcore/mcp-auth-proxy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

COPY --chown=65532:65532 ${TARGETPLATFORM}/mcp-auth-proxy /usr/local/bin/mcp-auth-proxy

# The MIT license and the upstream licences recorded in the notices both
# require the notice to travel with the distribution, and an image is a
# distribution. The files go in a project-named subdirectory so they add to
# /licenses instead of replacing it.
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/mcp-auth-proxy/

# Numeric nonroot uid/gid so the image works with read-only root filesystems and
# `runAsNonRoot` admission policies that cannot resolve names.
USER 65532:65532

# All mutable state (SQLite database, signing secret) lives here; mount a volume.
VOLUME ["/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/mcp-auth-proxy"]
CMD ["serve", "--config", "/data/config.yaml"]
