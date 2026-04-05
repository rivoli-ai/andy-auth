# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Trust corporate root CAs from the centralized certs/ directory
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=certs . /usr/local/share/ca-certificates/corporate/
RUN find /usr/local/share/ca-certificates/corporate/ -name '.git*' -delete 2>/dev/null || true && \
    find /usr/local/share/ca-certificates/corporate/ -name 'README.md' -delete 2>/dev/null || true && \
    update-ca-certificates

# SSL / NuGet hardening for corporate environments
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs \
    DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0 \
    NUGET_CERT_REVOCATION_MODE=off \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NUGET_SIGNATURE_VERIFICATION=false

# Copy csproj and restore
COPY src/Andy.Auth.Server/Andy.Auth.Server.csproj src/Andy.Auth.Server/
RUN dotnet restore src/Andy.Auth.Server/Andy.Auth.Server.csproj

# Copy source and build
COPY src/Andy.Auth.Server/ src/Andy.Auth.Server/
RUN dotnet publish src/Andy.Auth.Server/Andy.Auth.Server.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Generate a self-signed dev certificate
RUN mkdir -p /https && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /tmp/dev.key -out /tmp/dev.crt \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1" && \
    openssl pkcs12 -export -out /https/aspnetapp.pfx \
      -inkey /tmp/dev.key -in /tmp/dev.crt -passout pass:devcert && \
    rm -f /tmp/dev.key /tmp/dev.crt

# Entrypoint: trust custom CAs at runtime, then start the app
RUN printf '#!/bin/sh\nset -e\nif ls /usr/local/share/ca-certificates/custom/*.crt 1>/dev/null 2>&1 || ls /usr/local/share/ca-certificates/custom/*.pem 1>/dev/null 2>&1; then\n    update-ca-certificates 2>/dev/null || true\nfi\nexec "$@"\n' > /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx \
    ASPNETCORE_Kestrel__Certificates__Default__Password=devcert \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["dotnet", "Andy.Auth.Server.dll"]
