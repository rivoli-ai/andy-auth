# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

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

ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx \
    ASPNETCORE_Kestrel__Certificates__Default__Password=devcert

ENTRYPOINT ["dotnet", "Andy.Auth.Server.dll"]
