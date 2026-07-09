# eShield GitHub Release 发布脚本（PowerShell）
# 用法：
#   $env:GH_TOKEN = "ghp_xxx"
#   .\scripts\publish-release.ps1
#
# 前置条件：
#   1. 本地已打 tag 并推送到 origin：git push origin <TAG>
#   2. 已设置 GH_TOKEN（Classic token，需要 repo 权限）
#   3. 默认产物为 target/x86_64-unknown-linux-musl/release/eshield 和
#      target/bpfel-unknown-none/release/eshield；也可通过 $env:ASSET_DIR 指定目录

$Repo = "BlkSword/eShield"
$VersionLine = Get-Content eshield/Cargo.toml | Select-String -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $VersionLine) {
    Write-Host "错误：无法从 eshield/Cargo.toml 读取版本号" -ForegroundColor Red
    exit 1
}
$Version = $VersionLine.Matches.Groups[1].Value
$Tag = "v$Version"
$DefaultAssets = @(
    "target/x86_64-unknown-linux-musl/release/eshield",
    "target/bpfel-unknown-none/release/eshield"
)
$AssetDir = $env:ASSET_DIR

if (-not $env:GH_TOKEN) {
    Write-Host "错误：请先设置 GH_TOKEN 环境变量" -ForegroundColor Red
    Write-Host "示例：`$env:GH_TOKEN = 'ghp_xxxxxxxxxxxx'"
    exit 1
}

$Token = $env:GH_TOKEN
$Headers = @{ Authorization = "token $Token"; Accept = "application/vnd.github.v3+json" }

function Invoke-GitHubApiJson {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body = $null
    )
    $Params = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        ContentType = "application/json"
        UseBasicParsing = $true
    }
    if ($Body) { $Params.Body = $Body }
    try {
        $resp = Invoke-WebRequest @Params
        return @{ StatusCode = $resp.StatusCode; Content = $resp.Content }
    } catch {
        $err = $_
        $status = 0
        $msg = $err.Exception.Message
        if ($err.Exception.Response) {
            $status = [int]$err.Exception.Response.StatusCode
            $stream = $err.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $msg = $reader.ReadToEnd()
        }
        return @{ StatusCode = $status; Content = $msg }
    }
}

Write-Host "==> 检查 GitHub 上是否已存在 release $Tag"
$Existing = Invoke-GitHubApiJson -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag" -Method GET
if ($Existing.StatusCode -eq 200) {
    Write-Host "错误：GitHub 上已存在 $Tag release，请先删除或更换版本号" -ForegroundColor Red
    exit 1
}

Write-Host "==> 从 CHANGELOG.md 提取 $Tag 发布说明"
$Lines = Get-Content CHANGELOG.md
$BodyLines = @()
$InSection = $false
foreach ($Line in $Lines) {
    if ($Line -match "^## \$([regex]::Escape($Version))") {
        $InSection = $true
        continue
    }
    if ($Line -match '^## ') {
        $InSection = $false
    }
    if ($InSection) {
        $BodyLines += $Line
    }
}
$Body = $BodyLines -join "`n"
if ([string]::IsNullOrWhiteSpace($Body)) {
    Write-Host "警告：未从 CHANGELOG.md 提取到 $Tag 内容，使用默认说明"
    $Body = "eShield $Tag release."
}

Write-Host "==> 创建 GitHub Release $Tag"
$ReleaseData = @{
    tag_name = $Tag
    name = "eShield $Tag"
    body = $Body
    draft = $false
    prerelease = $false
}
$ReleaseBody = $ReleaseData | ConvertTo-Json

$Response = Invoke-GitHubApiJson -Uri "https://api.github.com/repos/$Repo/releases" -Method POST -Body $ReleaseBody
if ($Response.StatusCode -ne 201) {
    Write-Host "创建 release 失败：" -ForegroundColor Red
    Write-Host $Response.Content
    exit 1
}

$Release = $Response.Content | ConvertFrom-Json
$UploadUrl = $Release.upload_url -replace '\{\?name,label\}$', ''

Write-Host "==> 上传产物"
$Assets = @()
if ($AssetDir -and (Test-Path $AssetDir -PathType Container)) {
    $Assets = Get-ChildItem -Path $AssetDir -File | ForEach-Object { $_.FullName }
} else {
    $Assets = $DefaultAssets | Where-Object { Test-Path $_ }
}

if ($Assets.Count -eq 0) {
    Write-Host "错误：未找到任何产物" -ForegroundColor Red
    exit 1
}

foreach ($Asset in $Assets) {
    $Name = Split-Path $Asset -Leaf
    Write-Host "  上传 $Name ..."
    try {
        Invoke-WebRequest -Uri "$UploadUrl?name=$Name" -Method POST `
            -Headers $Headers -ContentType "application/octet-stream" `
            -InFile $Asset -UseBasicParsing | Out-Null
        Write-Host "  ✓ $Name" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ $Name 上传失败" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

Write-Host ""
Write-Host "==> 发布完成：https://github.com/$Repo/releases/tag/$Tag"
