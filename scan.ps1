# scan.ps1
# Запуск ffuf по сайту
# Автор: AquaWayne
# https://github.com/AquaWayne
#
# Запуск:
#   .\scan.cmd https://example.ru
#   .\scan.cmd https://example.ru -Insecure -Fc 404,403
#   .\scan.cmd https://example.ru -Out result.json

param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [string]$Wordlist,

    # скрыть коды
    [string]$Fc = "404",

    # запросов в секунду
    [int]$Rate = 40,

    # потоков
    [int]$Threads = 20,

    # игнор сертификата
    [switch]$Insecure,

    # свой заголовок
    [string]$Header,

    # файл отчёта
    [string]$Out,

    [string]$OutFormat = "json",

    # только находки
    [switch]$Silent
)

$root = $PSScriptRoot
$ffuf = Join-Path $root "ffuf.exe"
if (-not (Test-Path -LiteralPath $ffuf)) {
    throw "ffuf.exe не найден рядом со скриптом. Соберите его: go build -o ffuf.exe ."
}

# словарь по умолчанию
if (-not $Wordlist) {
    $Wordlist = Join-Path $root "wordlists\common.txt"
}
if (-not (Test-Path -LiteralPath $Wordlist)) {
    throw "Словарь не найден: $Wordlist"
}

# ffuf требует FUZZ в url
if ($Url -notmatch 'FUZZ') {
    $Url = $Url.TrimEnd('/') + '/FUZZ'
}

$ffufArgs = @(
    "-u", $Url,
    "-w", $Wordlist,
    "-fc", $Fc,
    "-rate", "$Rate",
    "-t", "$Threads"
)

if (-not $Silent) { $ffufArgs += "-c" }
if ($Silent)      { $ffufArgs += "-s" }
if ($Insecure)    { $ffufArgs += "-k" }
if ($Header)      { $ffufArgs += @("-H", $Header) }
if ($Out)         { $ffufArgs += @("-o", $Out, "-of", $OutFormat) }

Write-Host "Запуск: ffuf.exe $($ffufArgs -join ' ')" -ForegroundColor Cyan
Write-Host ""

# ffuf пишет прогресс в stderr
$ErrorActionPreference = "Continue"
& $ffuf @ffufArgs

$code = $LASTEXITCODE
if ($null -eq $code) { $code = 0 }
exit $code
