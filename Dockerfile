FROM mcr.microsoft.com/dotnet/core/aspnet:3.0-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.0-buster AS build
WORKDIR /src
COPY ["rde.edu.do_jericho_walls.csproj", ""]
RUN dotnet restore "rde.edu.do_jericho_walls.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "rde.edu.do_jericho_walls.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "rde.edu.do_jericho_walls.csproj" -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "rde.edu.do_jericho_walls.dll"]