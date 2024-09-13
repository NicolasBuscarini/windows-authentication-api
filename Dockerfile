# Usar a imagem base do .NET 8 SDK para a fase de constru��o
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copiar os arquivos csproj e restaurar depend�ncias
COPY /src/WindowsAuthentication.Api/WindowsAuthentication.Api.csproj ./src/WindowsAuthentication.Api/

WORKDIR /app/src/WindowsAuthentication.Api
RUN dotnet restore

# Copiar o restante dos arquivos e compilar a aplica��o
WORKDIR /app
COPY . . 
RUN dotnet publish -c Release -o out

# Construir a imagem de produ��o com as depend�ncias do Kerberos
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Instalar pacotes necess�rios para autentica��o Kerberos
RUN apt-get update && \
    apt-get install -y libkrb5-3 libgssapi-krb5-2 krb5-user

COPY --from=build-env /app/out .

# Definir o ponto de entrada da aplica��o
ENTRYPOINT ["dotnet", "WindowsAuthentication.Api.dll"]
