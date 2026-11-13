# Build from the repo root:  docker build -f src/DreaminGeek.Siem.Web/Dockerfile -t ghcr.io/dreamingeek/dg-siem-server .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG VERSION=0.1.0
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props .editorconfig ./
COPY src/ src/
# Install scripts embedded in the server for the agent packages it builds.
COPY deploy/agent/ deploy/agent/
COPY LICENSE ./
RUN dotnet publish src/DreaminGeek.Siem.Web/DreaminGeek.Siem.Web.csproj -c Release -p:Version="${VERSION#v}" -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
LABEL org.opencontainers.image.source="https://github.com/dreamingeek/dg-siem"
WORKDIR /app
COPY --from=build /app .
# PKI (agent CA) and data-protection keys live here; mount a volume and back it up.
RUN mkdir -p /var/lib/dg-siem/pki /var/lib/dg-siem/keys /var/lib/dg-siem/agent-packages && chown -R $APP_UID /var/lib/dg-siem
# Ports are set by Server__HttpPort/AgentPort; clear the base image default so Kestrel does not warn.
ENV Server__HttpPort=8080 Server__AgentPort=8443 ASPNETCORE_HTTP_PORTS=
# 8080: web UI (put behind your reverse proxy). 8443: agent API with its own TLS + client certs (raw TCP only).
EXPOSE 8080 8443
USER $APP_UID
ENTRYPOINT ["dotnet", "dg-siem-server.dll"]
