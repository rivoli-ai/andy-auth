# syntax=docker/dockerfile:1
#
# Base images are pinned to a patch tag rather than the floating `8.0` so a
# rebuild is reproducible and a base-image bump is a reviewable commit
# (andy-auth#126). Update policy: bump both tags together on the monthly .NET
# patch cadence, or immediately for a CVE affecting the runtime.
ARG DOTNET_SDK_TAG=8.0.423-noble
ARG DOTNET_RUNTIME_TAG=8.0.29-noble

# ──────────────────────────────────────────────────────────────────────────────
# Build stage
# ──────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_TAG} AS build
WORKDIR /src

# Corporate TLS interception breaks NuGet restore behind some networks. The
# accommodations for it are opt-in build args rather than baked-in defaults
# (andy-auth#126): this image previously shipped with
# DOTNET_NUGET_SIGNATURE_VERIFICATION=false and NUGET_CERT_REVOCATION_MODE=off
# unconditionally, which silently disabled package-signature verification and
# revocation checking for an authentication service — exactly the supply chain
# where they matter most.
#
#   docker build --build-arg TRUST_CORPORATE_CA=true \
#                --build-context certs=./certs .
#
ARG TRUST_CORPORATE_CA=false
ARG NUGET_CERT_REVOCATION_MODE=online

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    NUGET_CERT_REVOCATION_MODE=${NUGET_CERT_REVOCATION_MODE} \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs

# Corporate root CAs, only when explicitly requested. `certs` is a named build
# context; `docker compose build` supplies it via additional_contexts.
COPY --from=certs . /tmp/corporate-ca/
RUN set -eu; \
    if [ "${TRUST_CORPORATE_CA}" = "true" ]; then \
        apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
        rm -rf /var/lib/apt/lists/*; \
        find /tmp/corporate-ca/ -name '.git*' -delete 2>/dev/null || true; \
        find /tmp/corporate-ca/ -name 'README.md' -delete 2>/dev/null || true; \
        cp -a /tmp/corporate-ca/. /usr/local/share/ca-certificates/corporate/ 2>/dev/null || true; \
        update-ca-certificates; \
    fi; \
    rm -rf /tmp/corporate-ca

# Central package versions must be present or the versionless PackageReferences
# fail to resolve (andy-auth#129).
#
# nuget.config and local-packages/ are required too: Andy.Telemetry is consumed
# from the checked-in local feed and is not published to nuget.org, so restore
# inside the image fails without them. That is why `docker build` had been
# broken since the OT4 telemetry work — the image was never rebuilt from a
# clean context after that dependency landed.
COPY Directory.Build.props Directory.Packages.props nuget.config ./
COPY local-packages/ local-packages/
COPY src/Andy.Auth.Server/Andy.Auth.Server.csproj src/Andy.Auth.Server/
RUN dotnet restore src/Andy.Auth.Server/Andy.Auth.Server.csproj

COPY src/Andy.Auth.Server/ src/Andy.Auth.Server/
RUN dotnet publish src/Andy.Auth.Server/Andy.Auth.Server.csproj \
        -c Release -o /app/publish /p:UseAppHost=false

# ──────────────────────────────────────────────────────────────────────────────
# Runtime stage
# ──────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_RUNTIME_TAG}
WORKDIR /app

# openssl is needed only to mint the development certificate below; ca-certificates
# ships in the base image. Nothing else is installed — the build SDK, source and
# NuGet cache all stay in the build stage.
RUN apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Self-signed certificate for the docker-compose development stack, which runs
# Kestrel on https://+:5001. Hosted deployments terminate TLS at the edge and
# serve plain HTTP on $PORT, so this is never used there — but it has to exist
# for `docker compose up` to keep working.
#
# The password is a literal precisely because this key protects nothing: it is
# a throwaway localhost certificate generated at build time, identical in every
# image, and useless against any real name.
RUN mkdir -p /https /data/keys && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /tmp/dev.key -out /tmp/dev.crt \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1" && \
    openssl pkcs12 -export -out /https/aspnetapp.pfx \
      -inkey /tmp/dev.key -in /tmp/dev.crt -passout pass:devcert && \
    rm -f /tmp/dev.key /tmp/dev.crt && \
    chown -R $APP_UID:$APP_UID /https /data /app

ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx \
    ASPNETCORE_Kestrel__Certificates__Default__Password=devcert \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

# Least privilege (andy-auth#126). $APP_UID is the non-root user the .NET 8
# base images provide. Writable paths are limited to the two the service needs:
# /data/keys for the persisted OpenIddict signing keypair, and /https for the
# development certificate above.
#
# Runtime CA injection is deliberately gone with it: the old entrypoint ran
# update-ca-certificates on every start, which requires root. Corporate CAs are
# now a build-time concern (TRUST_CORPORATE_CA above), so the running process
# never needs write access to the system trust store.
USER $APP_UID

# No HEALTHCHECK instruction: probing it would mean shipping curl or wget into
# the runtime image, against the "no unnecessary tools" goal, and Docker's
# health concept has no readiness counterpart anyway. The orchestrator probes
# the endpoints directly — /health for liveness, /ready (unhealthy until
# migration and required seeding finish) for traffic admission. CI exercises
# both against a real container; see the container-smoke job.

ENTRYPOINT ["dotnet", "Andy.Auth.Server.dll"]
