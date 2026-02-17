# Build script for RedPivot on Windows

param(
    [string]$Version = "dev"
)

$BuildTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$LdFlags = "-s -w -X main.version=$Version"

Write-Host "Building RedPivot $Version..."

# Create output directory
New-Item -ItemType Directory -Force -Path bin | Out-Null

# Build server
Write-Host "Building redd (server)..."
$env:CGO_ENABLED = 0
go build -ldflags $LdFlags -o bin\redd.exe .\cmd\redd

# Build client
Write-Host "Building redctl (client)..."
go build -ldflags $LdFlags -o bin\redctl.exe .\cmd\redctl

Write-Host "Build complete!"
Write-Host "Binaries:"
Get-ChildItem bin
