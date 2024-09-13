# Usar a imagem base do .NET 8 SDK para a fase de construção
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copiar os arquivos csproj e restaurar dependências
COPY /src/WindowsAuthentication.Api/WindowsAuthentication.Api.csproj ./src/WindowsAuthentication.Api/

WORKDIR /app/src/WindowsAuthentication.Api
RUN dotnet restore

# Copiar o restante dos arquivos e compilar a aplicação
WORKDIR /app
COPY . . 
RUN dotnet publish -c Release -o out

# Construir a imagem de produção com as dependências do Kerberos
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Instalar pacotes necessários para autenticação Kerberos
RUN apt-get update && \
    apt-get install -y libkrb5-3 libgssapi-krb5-2 krb5-user

COPY --from=build-env /app/out .

# Definir o ponto de entrada da aplicação
ENTRYPOINT ["dotnet", "WindowsAuthentication.Api.dll"]
