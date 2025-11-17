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
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "Andy.Auth.Server.dll"]
