param(
    [string]$Configuration = "release",
    [string]$PackageName = "WatchApiRust-portable",
    [switch]$BundleLiteLLMOffline,
    [string]$PythonVersion = "3.11.9",
    [string]$PythonEmbeddableZip = "",
    [string]$Wheelhouse = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $Root
$TargetDir = Join-Path $Root "target\$Configuration"
$DistDir = Join-Path $RepoRoot "dist"
$StageDir = Join-Path $DistDir $PackageName
$ZipPath = Join-Path $DistDir "$PackageName.zip"
$CacheDir = Join-Path $Root ".package-cache"
$DefaultWheelhouse = Join-Path $CacheDir "wheelhouse"
$DefaultPythonCache = Join-Path $CacheDir "python-embed"

function Find-Python {
    $candidates = @(
        @("python", @()),
        @("python3", @()),
        @("py", @("-3.14")),
        @("py", @("-3.11")),
        @("py", @("-3.10")),
        @("py", @("-3"))
    )
    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        $args = $candidate[1]
        & $exe @args -c "import sys; print(sys.executable)" *> $null
        if ($LASTEXITCODE -eq 0) {
            return @{ Exe = $exe; Args = $args }
        }
    }
    throw "找不到可用于准备 wheelhouse 的 Python。请安装 Python 3.11+，或手动提供 -Wheelhouse。"
}

function Invoke-Checked {
    param(
        [string]$Exe,
        [object[]]$ArgumentList,
        [string]$ErrorMessage
    )
    & $Exe @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw $ErrorMessage
    }
}

function Expand-Zip-Clean {
    param(
        [string]$Zip,
        [string]$Destination
    )
    if (Test-Path $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Expand-Archive -LiteralPath $Zip -DestinationPath $Destination -Force
}

function Enable-Python-Embed-SitePackages {
    param([string]$PythonDir)
    $pth = Get-ChildItem -LiteralPath $PythonDir -Filter "python*._pth" | Select-Object -First 1
    if (-not $pth) {
        throw "Python embeddable 缺少 python*._pth：$PythonDir"
    }
    $lines = Get-Content -LiteralPath $pth.FullName
    $out = New-Object System.Collections.Generic.List[string]
    $hasSite = $false
    $hasLib = $false
    foreach ($line in $lines) {
        if ($line.Trim() -eq "#import site") {
            $out.Add("import site")
            $hasSite = $true
        } elseif ($line.Trim() -eq "import site") {
            $out.Add($line)
            $hasSite = $true
        } else {
            $out.Add($line)
        }
        if ($line.Trim() -eq "Lib\site-packages") {
            $hasLib = $true
        }
    }
    if (-not $hasLib) {
        $out.Insert([Math]::Max(0, $out.Count - 1), "Lib\site-packages")
    }
    if (-not $hasSite) {
        $out.Add("import site")
    }
    Set-Content -LiteralPath $pth.FullName -Encoding ASCII -Value $out
}

function Prepare-LiteLLM-Offline {
    param(
        [string]$StageDir,
        [string]$PythonVersion,
        [string]$PythonEmbeddableZip,
        [string]$Wheelhouse
    )

    New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
    if ([string]::IsNullOrWhiteSpace($Wheelhouse)) {
        $Wheelhouse = $DefaultWheelhouse
    }
    if ([string]::IsNullOrWhiteSpace($PythonEmbeddableZip)) {
        $PythonEmbeddableZip = Join-Path $DefaultPythonCache "python-$PythonVersion-embed-amd64.zip"
    }

    if (-not (Test-Path $PythonEmbeddableZip)) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $PythonEmbeddableZip) | Out-Null
        $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
        Write-Host "下载 Python embeddable：$url"
        Invoke-WebRequest -Uri $url -OutFile $PythonEmbeddableZip
    }

    $LiteLLMDir = Join-Path $StageDir "LiteLLM"
    $PythonDir = Join-Path $LiteLLMDir "python"
    $SitePackages = Join-Path $PythonDir "Lib\site-packages"
    $DriveRoot = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $StageDir).Path)
    $InstallTarget = Join-Path $DriveRoot "watchapi-litellm-sp"
    $PipTemp = Join-Path $DriveRoot "watchapi-pip-tmp"
    Expand-Zip-Clean -Zip $PythonEmbeddableZip -Destination $PythonDir
    Enable-Python-Embed-SitePackages -PythonDir $PythonDir
    New-Item -ItemType Directory -Force -Path $SitePackages | Out-Null
    $EmbedPython = Join-Path $PythonDir "python.exe"

    $python = Find-Python
    if (-not (Test-Path $Wheelhouse)) {
        New-Item -ItemType Directory -Force -Path $Wheelhouse | Out-Null
    }
    $PipWheel = Get-ChildItem -LiteralPath $Wheelhouse -Filter "pip-*.whl" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $PipWheel) {
        Write-Host "下载 pip wheel 到：$Wheelhouse"
        Invoke-Checked -Exe $python.Exe -ArgumentList ($python.Args + @("-m", "pip", "download", "pip", "--dest", $Wheelhouse)) -ErrorMessage "下载 pip wheel 失败"
        $PipWheel = Get-ChildItem -LiteralPath $Wheelhouse -Filter "pip-*.whl" | Sort-Object Name -Descending | Select-Object -First 1
    }
    $PipModule = Join-Path $PipWheel.FullName "pip"

    if (-not (Test-Path $Wheelhouse) -or -not (Get-ChildItem -LiteralPath $Wheelhouse -Filter "*.whl" -ErrorAction SilentlyContinue)) {
        New-Item -ItemType Directory -Force -Path $Wheelhouse | Out-Null
        Write-Host "下载 LiteLLM 离线 wheels 到：$Wheelhouse"
        Invoke-Checked -Exe $EmbedPython -ArgumentList @($PipModule, "download", "litellm[proxy]", "--dest", $Wheelhouse) -ErrorMessage "下载 LiteLLM wheels 失败"
    } elseif (-not (Get-ChildItem -LiteralPath $Wheelhouse -Filter "litellm-*.whl" -ErrorAction SilentlyContinue)) {
        Write-Host "补齐 LiteLLM 离线 wheels 到：$Wheelhouse"
        Invoke-Checked -Exe $EmbedPython -ArgumentList @($PipModule, "download", "litellm[proxy]", "--dest", $Wheelhouse) -ErrorMessage "下载 LiteLLM wheels 失败"
    }

    if (Test-Path $InstallTarget) {
        Remove-Item -LiteralPath $InstallTarget -Recurse -Force
    }
    if (Test-Path $PipTemp) {
        Remove-Item -LiteralPath $PipTemp -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $InstallTarget | Out-Null
    New-Item -ItemType Directory -Force -Path $PipTemp | Out-Null

    Write-Host "离线安装 LiteLLM 到临时短路径：$InstallTarget"
    $oldTemp = $env:TEMP
    $oldTmp = $env:TMP
    $env:TEMP = $PipTemp
    $env:TMP = $PipTemp
    try {
        Invoke-Checked -Exe $EmbedPython -ArgumentList @($PipModule, "install", "--no-index", "--find-links", $Wheelhouse, "--target", $InstallTarget, "litellm[proxy]") -ErrorMessage "离线安装 LiteLLM 失败"
    } finally {
        $env:TEMP = $oldTemp
        $env:TMP = $oldTmp
    }

    Get-ChildItem -LiteralPath $InstallTarget -Recurse -Directory -Filter "guardrail_benchmarks" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $InstallTarget -Force |
        Copy-Item -Destination $SitePackages -Recurse -Force
    Invoke-Checked -Exe $EmbedPython -ArgumentList @("-c", "import litellm; import fastapi; import uvicorn; print('LiteLLM offline runtime OK')") -ErrorMessage "LiteLLM 内置运行时校验失败"
    Remove-Item -LiteralPath $InstallTarget -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $PipTemp -Recurse -Force -ErrorAction SilentlyContinue

    $CmdPath = Join-Path $LiteLLMDir "litellm.cmd"
$CmdText = @"
@echo off
set "WATCHAPI_LITELLM_HOME=%~dp0"
"%~dp0python\python.exe" -c "import sys; from litellm import run_server; sys.exit(run_server())" %*
"@
    Set-Content -LiteralPath $CmdPath -Encoding ASCII -Value $CmdText

    $Readme = Join-Path $LiteLLMDir "README.txt"
    Set-Content -LiteralPath $Readme -Encoding UTF8 -Value @"
WatchApi bundled LiteLLM

This directory is generated by package-release.ps1 -BundleLiteLLMOffline.
It contains Python embeddable plus LiteLLM proxy dependencies installed from wheelhouse.
Run entry:
  LiteLLM\litellm.cmd
"@
}

Push-Location $Root
try {
    cargo build --release --workspace
} finally {
    Pop-Location
}

if (Test-Path $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "Configs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "ProxyConfigs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "logs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "assets") | Out-Null

Copy-Item -LiteralPath (Join-Path $TargetDir "watchapi-gui.exe") -Destination (Join-Path $StageDir "watchapi-gui.exe") -Force
Copy-Item -LiteralPath (Join-Path $TargetDir "watchapi-cli.exe") -Destination (Join-Path $StageDir "watchapi-cli.exe") -Force
Copy-Item -LiteralPath (Join-Path $Root "README.md") -Destination (Join-Path $StageDir "README.md") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "assets\watchapi.ico") -Destination (Join-Path $StageDir "assets\watchapi.ico") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "assets\watchapi.png") -Destination (Join-Path $StageDir "assets\watchapi.png") -Force

$PromptLibrary = Join-Path $StageDir "prompt-library.json"
if (-not (Test-Path $PromptLibrary)) {
    Set-Content -LiteralPath $PromptLibrary -Encoding UTF8 -Value "{`n  `"prompts`": []`n}"
}

if ($BundleLiteLLMOffline) {
    Prepare-LiteLLM-Offline -StageDir $StageDir -PythonVersion $PythonVersion -PythonEmbeddableZip $PythonEmbeddableZip -Wheelhouse $Wheelhouse
}

if (Test-Path $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
$PackageItems = Get-ChildItem -LiteralPath $StageDir -Force
Compress-Archive -LiteralPath $PackageItems.FullName -DestinationPath $ZipPath -Force

Write-Host "已构建：$StageDir"
Write-Host "已打包：$ZipPath"
