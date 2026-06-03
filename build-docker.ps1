# PowerShell script for building psh using Docker
# Usage:
#   .\build-docker.ps1              构建依赖库并编译 psh
#   .\build-docker.ps1 -Action libs 仅构建依赖库
#   .\build-docker.ps1 -Action build 仅编译 psh
#   .\build-docker.ps1 -Action clean 清理 psh 构建产物
#   .\build-docker.ps1 -Arch arm    交叉编译 (arm-linux-gnueabihf-gcc)

param(
    [ValidateSet("all", "libs", "build", "clean")]
    [string]$Action = "all",
    [ValidateSet("local", "arm")]
    [string]$Arch = "local"
)

# Configuration
$ImageName = "docker.cnb.cool/smk.k/alpha/dev-env/alpha-dev-env"
$ContainerName = "psh-builder"
$SourceDir = $PSScriptRoot
$CrossCompilerPath = "/opt/gcc-arm-8.3-2019.03-x86_64-arm-linux-gnueabihf/bin"

Write-Host "=== psh Docker Build Script ===" -ForegroundColor Cyan
Write-Host "Source directory : $SourceDir" -ForegroundColor Gray
Write-Host "Action           : $Action" -ForegroundColor Gray
Write-Host "Arch             : $Arch" -ForegroundColor Gray

# Check if Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed or not in PATH"
    exit 1
}

# Build docker run arguments
$DockerArgs = @(
    "run",
    "--rm",
    "--name", $ContainerName,
    "-v", "${SourceDir}:/workspace",
    "-w", "/workspace"
)

# Cross-compile: set PATH and ARCH env
if ($Arch -eq "arm") {
    $DockerArgs += "-e", "PATH=${CrossCompilerPath}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    $DockerArgs += "-e", "ARCH=arm"
    Write-Host "Cross-compile    : arm-linux-gnueabihf-gcc" -ForegroundColor Yellow
} else {
    $DockerArgs += "-e", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

$DockerArgs += $ImageName

# Build command: call build.sh
$BuildCmd = "bash build.sh $Action"
$DockerArgs += "bash", "-c", $BuildCmd

Write-Host "Running: docker $($DockerArgs -join ' ')" -ForegroundColor Gray

# Execute docker command
& docker $DockerArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild completed successfully!" -ForegroundColor Green

    # List generated files
    $pshBin = Join-Path $SourceDir "psh"
    if (Test-Path $pshBin) {
        $size = (Get-Item $pshBin).Length
        Write-Host "  - psh ($size bytes)" -ForegroundColor Gray
    }
} else {
    Write-Error "Build failed with exit code: $LASTEXITCODE"
    exit $LASTEXITCODE
}
