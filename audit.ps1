# audit.ps1
# Пассивный аудит сайта
# Один HTML-отчёт
# Автор: AquaWayne
# https://github.com/AquaWayne
#
# Запуск:
#   .\audit.cmd https://example.ru
#   .\audit.cmd https://example.ru -Ffuf
#   .\audit.cmd https://example.ru -Out report.html -Insecure

param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [string]$Out = "audit-report.html",

    # ffuf по словарю
    [switch]$Ffuf,

    [string]$Wordlist,

    [int]$Rate = 40,

    # игнор сертификата
    [switch]$Insecure,

    # csv для трекера
    [switch]$Csv,

    # разделитель csv
    [string]$CsvDelimiter = ";"
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = $PSScriptRoot
$tmp = Join-Path $PSScriptRoot ("_audit_tmp_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# аватар автора
$avatarB64 = ""
foreach ($a in @((Join-Path $root "assets\avatar-96.png"), (Join-Path $root "assets\avatar.png"))) {
    if (Test-Path -LiteralPath $a) {
        $avatarB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($a))
        break
    }
}

# нормализация url
if ($Url -notmatch '^https?://') { $Url = "https://" + $Url }
$Url = $Url.TrimEnd('/')
$hostName = ([uri]$Url).Host
$domain = $hostName -replace '^www\.', ''

$curl = "curl.exe"
$baseArgs = @("-sS", "--max-time", "15", "--connect-timeout", "8", "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SiteAudit/1.0")
if ($Insecure) { $baseArgs += "-k" }

# html-экранирование
function HtmlEnc([string]$s) {
    if ($null -eq $s) { return "" }
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '"', '&quot;'
    return $s
}

# склонение
function Plural([int]$n, [string]$one, [string]$few, [string]$many) {
    $m10 = $n % 10
    $m100 = $n % 100
    if ($m10 -eq 1 -and $m100 -ne 11) { return $one }
    if ($m10 -ge 2 -and $m10 -le 4 -and ($m100 -lt 12 -or $m100 -gt 14)) { return $few }
    return $many
}

# список проверок
$checks = New-Object System.Collections.ArrayList
function Add-Check([string]$category, [string]$name, [string]$status, [string]$detail, [string]$advice) {
    [void]$checks.Add([pscustomobject]@{
        Category = $category; Name = $name; Status = $status; Detail = $detail; Advice = $advice
    })
}

# оценки cvss
# v3.1, ориентировочно
$cvssMap = @{
    "Strict-Transport-Security (HSTS)" = @{ s = 3.7; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N" }
    "X-Frame-Options"                  = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" }
    "CSP frame-ancestors"              = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" }
    "Content-Security-Policy"          = @{ s = 3.6; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N" }
    "X-Content-Type-Options"           = @{ s = 3.1; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N" }
    "Referrer-Policy"                  = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
    "Permissions-Policy"               = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
    "Заголовок Server"                 = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "Заголовок X-Powered-By"           = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "CORS"                             = @{ s = 8.1; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" }
    "Флаги cookie"                     = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "HTTPS"                            = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Сертификат"                       = @{ s = 5.9; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Цепочка сертификата"              = @{ s = 5.9; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Срок действия"                    = @{ s = 5.9; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Версия протокола"                 = @{ s = 5.9; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Git-репозиторий"                  = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    ".env с секретами"                 = @{ s = 9.1; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" }
    "SVN-метаданные"                   = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Архив бэкапа"                     = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Дамп БД"                          = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "phpinfo()"                        = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "Apache server-status"             = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "Бэкап конфига WordPress"          = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }
    "Captcha на форме входа"           = @{ s = 3.7; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
    "CSRF-токен в формах"              = @{ s = 6.5; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" }
    "SPF"                              = @{ s = 3.7; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" }
    "DMARC"                            = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" }
    "Перебор путей (ffuf)"             = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
}

# оценка по имени
function Get-Cvss([string]$name) {
    if ($cvssMap.ContainsKey($name)) { return $cvssMap[$name] }
    return @{ s = 3.1; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
}

# уровень риска
function Get-Sev([double]$score) {
    if ($score -ge 9.0) { return @{ T = "Критично"; C = "#a40e26" } }
    if ($score -ge 7.0) { return @{ T = "Высоко"; C = "#cf222e" } }
    if ($score -ge 4.0) { return @{ T = "Средне"; C = "#bf8700" } }
    if ($score -gt 0)   { return @{ T = "Низко"; C = "#57606a" } }
    return @{ T = "Инфо"; C = "#57606a" }
}

# основной запрос
$hdrFile = Join-Path $tmp "hdr.txt"
$bodyFile = Join-Path $tmp "body.html"
$fmtFile = Join-Path $tmp "fmt.txt"

$args1 = $baseArgs + @("-L", "-D", $hdrFile, "-o", $bodyFile, "-w",
    "%{http_code}|%{url_effective}|%{time_total}|%{num_redirects}|%{ssl_verify_result}", $Url)

# основной запрос с повтором
$status = ""; $finalUrl = ""; $timeTotal = ""; $redirects = "0"; $sslVerify = ""
for ($try = 1; $try -le 2; $try++) {
    & $curl @args1 > $fmtFile 2>$null
    $fmt = (Get-Content -LiteralPath $fmtFile -Raw -ErrorAction SilentlyContinue)
    if ($fmt) { $fmt = $fmt.Trim() }
    if ($fmt -match '^(\d*)\|(.*)\|([\d,\.]*)\|(\d*)\|(\d*)') {
        $status = $Matches[1]; $finalUrl = $Matches[2]; $timeTotal = $Matches[3]; $redirects = $Matches[4]; $sslVerify = $Matches[5]
    }
    if ($status -and $status -ne "000") { break }
    Start-Sleep -Milliseconds 800
}

$headersRaw = ""
if (Test-Path -LiteralPath $hdrFile) { $headersRaw = Get-Content -LiteralPath $hdrFile -Raw }
$body = ""
if (Test-Path -LiteralPath $bodyFile) { $body = Get-Content -LiteralPath $bodyFile -Raw }

# блоки заголовков
$blocks = @()
if ($headersRaw) {
    $blocks = $headersRaw -split '(?:\r?\n){2,}' | Where-Object { $_ -match '^HTTP/' }
}

$finalHeaders = @{}   # заголовки финальные
$redirectChain = @()
foreach ($b in $blocks) {
    $lines = $b -split '\r?\n' | Where-Object { $_ -ne "" }
    if ($lines.Count -eq 0) { continue }
    $statusLine = $lines[0]
    $local = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $idx = $lines[$i].IndexOf(":")
        if ($idx -gt 0) {
            $n = $lines[$i].Substring(0, $idx).Trim().ToLower()
            $v = $lines[$i].Substring($idx + 1).Trim()
            if (-not $local.ContainsKey($n)) { $local[$n] = @() }
            $local[$n] += $v
        }
    }
    $code = "?"
    if ($statusLine -match 'HTTP/[\d\.]+\s+(\d{3})') { $code = $Matches[1] }
    $loc = ""
    if ($local.ContainsKey("location")) { $loc = $local["location"][0] }
    $redirectChain += [pscustomobject]@{ Code = $code; Location = $loc }
    $finalHeaders = $local
}

$lastCode = "?"
if ($redirectChain.Count -gt 0) { $lastCode = $redirectChain[$redirectChain.Count - 1].Code }
if (-not $status) { $status = $lastCode }

# чтение заголовка
function Get-HdrValue([string]$name) {
    if ($finalHeaders.ContainsKey($name)) { return ($finalHeaders[$name] -join "; ") }
    return ""
}

# сертификат
# curl -v на windows его не печатает
$certSubject = ""; $certIssuer = ""; $certExpire = ""; $certNotAfter = $null
$certChainOk = $null; $tlsProto = ""; $certError = ""
$certDaysLeft = ""
if ($Url -match '^https') {
    try {
        $u = [uri]$Url
        $port = 443
        if ($u.Port -gt 0) { $port = $u.Port }
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($u.Host, $port)
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($sn, $ce, $cc, $ce2) $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($u.Host)
        $tlsProto = "$($ssl.SslProtocol)"
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $certSubject = $cert.Subject
        $certIssuer = $cert.Issuer
        $certNotAfter = $cert.NotAfter
        $certDaysLeft = [int](($cert.NotAfter - (Get-Date)).TotalDays)
        $certExpire = $cert.NotAfter.ToString("dd.MM.yyyy")
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        $certChainOk = $chain.Build($cert)
        $ssl.Dispose()
        $tcp.Close()
    } catch {
        $certError = $_.Exception.Message
    }
}

# заголовки
$hsts = Get-HdrValue "strict-transport-security"
$xfo = Get-HdrValue "x-frame-options"
$csp = Get-HdrValue "content-security-policy"
$cspRO = Get-HdrValue "content-security-policy-report-only"
$xcto = Get-HdrValue "x-content-type-options"
$refpol = Get-HdrValue "referrer-policy"
$permpol = Get-HdrValue "permissions-policy"
$server = Get-HdrValue "server"
$xpb = Get-HdrValue "x-powered-by"

# HSTS
if ($Url -match '^https') {
    if ($hsts) {
        $maxAge = 0
        if ($hsts -match 'max-age=(\d+)') { $maxAge = [int]$Matches[1] }
        if ($maxAge -ge 15552000) {
            Add-Check "Заголовки" "Strict-Transport-Security (HSTS)" "pass" "max-age=$maxAge" "не требуется"
        } else {
            Add-Check "Заголовки" "Strict-Transport-Security (HSTS)" "warn" "max-age=$maxAge (мало)" "Рекомендуется max-age=31536000; includeSubDomains"
        }
    } else {
        Add-Check "Заголовки" "Strict-Transport-Security (HSTS)" "fail" "заголовок отсутствует" "Добавьте: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    }
}

# кликджекинг
$frameAncestors = ""
if ($csp -match "frame-ancestors\s+([^;]+)") { $frameAncestors = $Matches[1].Trim() }
if ($xfo) {
    $xfv = $xfo.ToLower()
    if ($xfv -match 'deny|sameorigin') {
        Add-Check "Кликджекинг" "X-Frame-Options" "pass" $xfo "не требуется"
    } else {
        Add-Check "Кликджекинг" "X-Frame-Options" "warn" "$xfo (устаревшее или некорректное значение)" "Используйте DENY или SAMEORIGIN"
    }
} elseif ($frameAncestors) {
    Add-Check "Кликджекинг" "X-Frame-Options" "pass" "нет, но есть CSP frame-ancestors" "XFO не нужен, если задан frame-ancestors"
} else {
    Add-Check "Кликджекинг" "X-Frame-Options" "fail" "заголовок отсутствует, frame-ancestors в CSP нет" "Сайт можно встроить в iframe. Добавьте X-Frame-Options: DENY (или CSP frame-ancestors 'self')"
}
if ($frameAncestors) {
    Add-Check "Кликджекинг" "CSP frame-ancestors" "pass" $frameAncestors "не требуется"
} else {
    Add-Check "Кликджекинг" "CSP frame-ancestors" "warn" "не задан" "Современная замена X-Frame-Options"
}

# CSP
if ($csp) {
    $cspLower = $csp.ToLower()
    if ($cspLower -match "unsafe-inline" -and $cspLower -match "script-src") {
        Add-Check "Заголовки" "Content-Security-Policy" "warn" "есть, но с 'unsafe-inline' в script-src" "unsafe-inline ослабляет защиту от XSS"
    } elseif ($cspLower -match "default-src") {
        Add-Check "Заголовки" "Content-Security-Policy" "pass" "задан" "не требуется"
    } else {
        Add-Check "Заголовки" "Content-Security-Policy" "warn" "задан, но без default-src" "Задайте default-src 'self' как базу"
    }
} elseif ($cspRO) {
    Add-Check "Заголовки" "Content-Security-Policy" "warn" "только report-only (ничего не блокирует)" "Переведите в боевой режим после отладки"
} else {
    Add-Check "Заголовки" "Content-Security-Policy" "fail" "отсутствует" "Основная защита от XSS. Начните с default-src 'self'"
}

# XCTO
if ($xcto -match 'nosniff') {
    Add-Check "Заголовки" "X-Content-Type-Options" "pass" $xcto "не требуется"
} else {
    Add-Check "Заголовки" "X-Content-Type-Options" "fail" "отсутствует или не nosniff" "Добавьте: X-Content-Type-Options: nosniff"
}

# referrer
if ($refpol) {
    if ($refpol -match 'no-referrer|strict-origin|same-origin') {
        Add-Check "Заголовки" "Referrer-Policy" "pass" $refpol "не требуется"
    } else {
        Add-Check "Заголовки" "Referrer-Policy" "warn" $refpol "Лучше strict-origin-when-cross-origin"
    }
} else {
    Add-Check "Заголовки" "Referrer-Policy" "warn" "отсутствует" "Добавьте: Referrer-Policy: strict-origin-when-cross-origin"
}

# permissions
if ($permpol) {
    Add-Check "Заголовки" "Permissions-Policy" "pass" "задан" "не требуется"
} else {
    Add-Check "Заголовки" "Permissions-Policy" "warn" "отсутствует" "Ограничьте camera/microphone/geolocation"
}

# раскрытие
if ($server -and $server -notmatch '^(cloudflare|nginx)$') {
    Add-Check "Раскрытие" "Заголовок Server" "warn" $server "Скройте версию ПО (ServerTokens Prod или server_tokens off)"
} elseif ($server) {
    Add-Check "Раскрытие" "Заголовок Server" "pass" $server "не требуется"
}
if ($xpb) {
    Add-Check "Раскрытие" "Заголовок X-Powered-By" "warn" $xpb "Уберите: выдаёт стек технологий"
}

# CORS
$acao = Get-HdrValue "access-control-allow-origin"
$acac = Get-HdrValue "access-control-allow-credentials"
if ($acao -eq "*" -and $acac -match 'true') {
    Add-Check "Раскрытие" "CORS" "fail" "Access-Control-Allow-Origin: * вместе с credentials" "Опасно: любой сайт читает ответы от имени пользователя"
} elseif ($acao -eq "*") {
    Add-Check "Раскрытие" "CORS" "warn" "Access-Control-Allow-Origin: *" "Допустимо для публичных API, но не для приватных данных"
} elseif ($acao) {
    Add-Check "Раскрытие" "CORS" "pass" $acao "не требуется"
}

# cookie
$cookieFails = @(); $cookieCount = 0
if ($finalHeaders.ContainsKey("set-cookie")) {
    foreach ($c in $finalHeaders["set-cookie"]) {
        $cookieCount++
        $cname = ($c -split '=')[0]
        $cl = $c.ToLower()
        $miss = @()
        if ($cl -notmatch ';\s*secure') { $miss += "Secure" }
        if ($cl -notmatch ';\s*httponly') { $miss += "HttpOnly" }
        if ($cl -notmatch ';\s*samesite') { $miss += "SameSite" }
        if ($miss.Count -gt 0) { $cookieFails += "$cname (нет: $($miss -join ', '))" }
    }
}
if ($cookieCount -eq 0) {
    Add-Check "Cookie" "Флаги cookie" "info" "страница не устанавливает cookie" "Проверьте флаги на странице логина"
} elseif ($cookieFails.Count -eq 0) {
    Add-Check "Cookie" "Флаги cookie" "pass" "все $cookieCount cookie с Secure/HttpOnly/SameSite" "не требуется"
} else {
    Add-Check "Cookie" "Флаги cookie" "warn" ($cookieFails -join "; ") "Добавьте Secure; HttpOnly; SameSite=Lax"
}

# TLS
if ($Url -match '^https') {
    if ($certError) {
        Add-Check "TLS" "Сертификат" "warn" "не удалось получить: $certError" "Проверьте, что порт 443 доступен"
    } else {
        if ($certChainOk -eq $true) {
            Add-Check "TLS" "Цепочка сертификата" "pass" "проверена, $tlsProto" "не требуется"
        } elseif ($Insecure) {
            Add-Check "TLS" "Цепочка сертификата" "warn" "не проходит проверку (запуск с -Insecure)" "Для боевого сайта нужен валидный сертификат"
        } else {
            Add-Check "TLS" "Цепочка сертификата" "fail" "не проходит проверку" "Браузер покажет предупреждение. Проверьте полноту цепочки"
        }
        if ($certDaysLeft -ne "") {
            if ($certDaysLeft -lt 0) {
                Add-Check "TLS" "Срок действия" "fail" "истёк $([math]::Abs($certDaysLeft)) дн. назад" "Обновите сертификат"
            } elseif ($certDaysLeft -lt 14) {
                Add-Check "TLS" "Срок действия" "warn" "осталось $certDaysLeft дн., до $certExpire" "Продлите заранее"
            } else {
                Add-Check "TLS" "Срок действия" "pass" "осталось $certDaysLeft дн., до $certExpire" "не требуется"
            }
        }
        if ($tlsProto -match 'Tls13|Tls12') {
            Add-Check "TLS" "Версия протокола" "pass" $tlsProto "не требуется"
        } elseif ($tlsProto) {
            Add-Check "TLS" "Версия протокола" "fail" $tlsProto "Отключите TLS 1.0 и 1.1"
        }
        Add-Check "TLS" "Издатель" "info" "$certIssuer" "не требуется"
    }
} else {
    Add-Check "TLS" "HTTPS" "fail" "сайт отдаётся по HTTP без шифрования" "Настройте HTTPS и редирект с HTTP"
}

# чувствительные пути
$sensitive = @(
    @{ P = "/.git/HEAD"; N = "Git-репозиторий" },
    @{ P = "/.env"; N = ".env с секретами" },
    @{ P = "/.svn/entries"; N = "SVN-метаданные" },
    @{ P = "/backup.zip"; N = "Архив бэкапа" },
    @{ P = "/db.sql"; N = "Дамп БД" },
    @{ P = "/phpinfo.php"; N = "phpinfo()" },
    @{ P = "/server-status"; N = "Apache server-status" },
    @{ P = "/wp-config.php.bak"; N = "Бэкап конфига WordPress" }
)
foreach ($s in $sensitive) {
    $code = & $curl @baseArgs -o NUL -w "%{http_code}" ($Url + $s.P) 2>$null
    $code = "$code".Trim()
    if ($code -in @("200", "206")) {
        Add-Check "Раскрытие" $s.N "fail" "$($s.P) отдаёт $code" "Закройте доступ: файл доступен из интернета"
    } elseif ($code -in @("301", "302", "401", "403")) {
        Add-Check "Раскрытие" $s.N "pass" "$($s.P) -> $code" "не требуется"
    }
}

# robots
$robots = & $curl @baseArgs -o NUL -w "%{http_code}" ($Url + "/robots.txt") 2>$null
if ("$robots".Trim() -eq "200") {
    $robotsBody = & $curl @baseArgs ($Url + "/robots.txt") 2>$null | Out-String
    $disallow = ($robotsBody -split '\r?\n' | Where-Object { $_ -match '^(Disallow|Allow)' }) -join "`n"
    if ($disallow.Length -gt 400) { $disallow = $disallow.Substring(0, 400) + "..." }
    Add-Check "Раскрытие" "robots.txt" "info" "найден. Список путей подсказывает цели" "Проверьте, что скрытые разделы закрыты авторизацией, а не только в robots.txt"
}

# формы
$hasForm = $body -match '<form'
if ($hasForm) {
    $forms = [regex]::Matches($body, '(?is)<form\b.*?</form>')
    $csrfMissing = 0; $captcha = $false; $passFields = 0
    foreach ($f in $forms) {
        $fh = $f.Value
        if ($fh -match 'type\s*=\s*["'']?password') { $passFields++ }
        if ($fh -match '(?i)(csrf|token|authenticity|_token|nonce)') { } else { $csrfMissing++ }
        if ($fh -match '(?i)(recaptcha|hcaptcha|turnstile|captcha)') { $captcha = $true }
    }
    if ($passFields -gt 0) {
        Add-Check "Формы" "Captcha на форме входа" $(if ($captcha) { "pass" } else { "warn" }) $(if ($captcha) { "обнаружена" } else { "не обнаружена в HTML" }) "Без captcha и лимитов возможен перебор паролей. Проверьте rate limit на стороне сервера"
    }
    if ($csrfMissing -gt 0) {
        Add-Check "Формы" "CSRF-токен в формах" "warn" "$csrfMissing из $($forms.Count) форм без видимого токена" "Проверьте вручную: токен может подставляться JS. CSRF позволяет отправлять действия от имени пользователя"
    } else {
        Add-Check "Формы" "CSRF-токен в формах" "pass" "токены найдены во всех формах" "не требуется"
    }
    $phoneField = $body -match '(?i)type\s*=\s*["'']?tel|name\s*=\s*["''][^"'']*(phone|tel|mobile)'
    if ($phoneField) {
        Add-Check "Формы" "Поле телефона" "info" "найдено. Подтверждение кода проверяется вручную" "Проверьте лимит попыток, срок жизни кода и лимит повторной отправки"
    }
    Add-Check "Формы" "Автозаполнение паролей" "info" "autocomplete проверяется вручную" "Лучше autocomplete='off' на полях с паролем"
} else {
    Add-Check "Формы" "Формы на странице" "info" "форм нет" "Проверьте страницы логина и регистрации отдельно"
}

# почта
try {
    $txt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join "" }
    $spf = @($txt | Where-Object { $_ -match '^v=spf1' })
    if ($spf.Count -gt 0) {
        $spfVal = $spf[0]
        $softFail = $spfVal -match '\-all'
        Add-Check "Почта" "SPF" $(if ($softFail) { "pass" } else { "warn" }) $spfVal $(if ($softFail) { "не требуется" } else { "Завершите политику на -all, иначе письма от поддельных отправителей проходят" })
    } else {
        Add-Check "Почта" "SPF" "fail" "запись не найдена" "Добавьте SPF: v=spf1 ... -all. Без него ваши адреса легко подделать"
    }
} catch { Add-Check "Почта" "SPF" "info" "DNS-запрос не удался" "не требуется" }

try {
    $dm = @(Resolve-DnsName -Name ("_dmarc." + $domain) -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join "" })
    if ($dm.Count -gt 0) {
        $dmVal = [string]$dm[0]
        if ($dmVal -match 'p=none') {
            Add-Check "Почта" "DMARC" "warn" "$dmVal" "p=none только мониторит: подделка не блокируется. Перейдите на p=quarantine или p=reject"
        } else {
            Add-Check "Почта" "DMARC" "pass" $dmVal "не требуется"
        }
    } else {
        Add-Check "Почта" "DMARC" "fail" "запись не найдена" "Добавьте _dmarc: v=DMARC1; p=quarantine; rua=mailto:..."
    }
} catch { Add-Check "Почта" "DMARC" "info" "DNS-запрос не удался" "не требуется" }

# ffuf
$ffufResults = @()
$ffufRan = $false
if ($Ffuf) {
    $ffufExe = Join-Path $root "ffuf.exe"
    if (-not (Test-Path -LiteralPath $ffufExe)) {
        Add-Check "Скрытые пути" "ffuf" "info" "ffuf.exe не найден" "Соберите: go build -o ffuf.exe ."
    } else {
        if (-not $Wordlist) { $Wordlist = Join-Path $root "wordlists\common.txt" }
        $ffufOut = Join-Path $tmp "ffuf.json"
        $ffufRan = $true
        Write-Host "ffuf: перебор путей (может занять время)..." -ForegroundColor DarkGray
        $ffufArgs = @("-u", ($Url + "/FUZZ"), "-w", $Wordlist, "-fc", "404",
            "-rate", "$Rate", "-t", "20", "-s", "-o", $ffufOut, "-of", "json")
        if ($Insecure) { $ffufArgs += "-k" }
        & $ffufExe @ffufArgs 2>$null | Out-Null
        if (Test-Path -LiteralPath $ffufOut) {
            try {
                $j = Get-Content -LiteralPath $ffufOut -Raw -Encoding UTF8 | ConvertFrom-Json
                $ffufResults = @($j.results)
            } catch { }
        }
        if ($ffufResults.Count -eq 0) {
            Add-Check "Скрытые пути" "Перебор путей (ffuf)" "pass" "скрытых путей не найдено" "не требуется"
        } else {
            Add-Check "Скрытые пути" "Перебор путей (ffuf)" "warn" "найдено $($ffufResults.Count) путей" "Проверьте, что каждый требует авторизации, где это нужно"
        }
    }
}

# доп. оценки cvss
$cvssMap["Cross-Origin-Opener-Policy"]    = @{ s = 3.1; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
$cvssMap["Cross-Origin-Embedder-Policy"]  = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
$cvssMap["Cross-Origin-Resource-Policy"]  = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" }
$cvssMap["X-Permitted-Cross-Domain-Policies"] = @{ s = 2.6; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" }
$cvssMap["CSP unsafe-eval"]               = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" }
$cvssMap["Смешанный контент"]             = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" }
$cvssMap["SRI у внешних скриптов"]        = @{ s = 3.7; v = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N" }
$cvssMap["target=_blank без noopener"]    = @{ s = 4.3; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" }
$cvssMap["Мягкая 404"]                    = @{ s = 3.1; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" }
$cvssMap["Сообщения об ошибках"]          = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
$cvssMap["Листинг каталога"]              = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
$cvssMap["Метод TRACE"]                   = @{ s = 5.3; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }
$cvssMap["Опасные HTTP-методы"]           = @{ s = 7.5; v = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" }
$cvssMap["Редирект с HTTP"]               = @{ s = 6.5; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" }
$cvssMap["Отражение Origin в CORS"]       = @{ s = 8.1; v = "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" }
$cvssMap["TLS 1.0 и 1.1"]                 = @{ s = 5.9; v = "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" }

# coop и corp
$coop = Get-HdrValue "cross-origin-opener-policy"
$coep = Get-HdrValue "cross-origin-embedder-policy"
$corp = Get-HdrValue "cross-origin-resource-policy"
$xpc = Get-HdrValue "x-permitted-cross-domain-policies"

if ($coop) {
    Add-Check "Заголовки" "Cross-Origin-Opener-Policy" "pass" $coop "не требуется"
} else {
    Add-Check "Заголовки" "Cross-Origin-Opener-Policy" "warn" "отсутствует" "Добавьте: Cross-Origin-Opener-Policy: same-origin"
}
if ($coep) {
    Add-Check "Заголовки" "Cross-Origin-Embedder-Policy" "pass" $coep "не требуется"
} else {
    Add-Check "Заголовки" "Cross-Origin-Embedder-Policy" "info" "отсутствует" "Нужен только если важна изоляция процесса"
}
if ($corp) {
    Add-Check "Заголовки" "Cross-Origin-Resource-Policy" "pass" $corp "не требуется"
} else {
    Add-Check "Заголовки" "Cross-Origin-Resource-Policy" "info" "отсутствует" "Ограничивает встраивание ресурсов чужими сайтами"
}
if ($xpc) {
    Add-Check "Заголовки" "X-Permitted-Cross-Domain-Policies" "pass" $xpc "не требуется"
} else {
    Add-Check "Заголовки" "X-Permitted-Cross-Domain-Policies" "info" "отсутствует" "Актуально для старых Flash и PDF"
}

# hsts preload
if ($hsts) {
    if ($hsts -match '(?i)preload') {
        Add-Check "Заголовки" "HSTS preload" "pass" "директива указана" "не требуется"
    } else {
        Add-Check "Заголовки" "HSTS preload" "info" "директивы нет" "Добавьте preload, если готовы к строгому режиму"
    }
}

# csp unsafe-eval
if ($csp) {
    if ($csp -match '(?i)unsafe-eval') {
        Add-Check "Заголовки" "CSP unsafe-eval" "warn" "разрешён unsafe-eval" "Уберите unsafe-eval, он ослабляет защиту от XSS"
    } else {
        Add-Check "Заголовки" "CSP unsafe-eval" "pass" "не найден" "не требуется"
    }
} else {
    Add-Check "Заголовки" "CSP unsafe-eval" "info" "CSP не задан, проверять нечего" "Сначала включите CSP"
}

# префиксы cookie
if ($cookieCount -gt 0 -and $finalHeaders.ContainsKey("set-cookie")) {
    $pref = @($finalHeaders["set-cookie"] | Where-Object { $_ -match '^\s*__(Host|Secure)-' }).Count
    if ($pref -eq $cookieCount) {
        Add-Check "Заголовки" "Префиксы cookie" "info" "используются __Host- или __Secure-" "не требуется"
    } else {
        Add-Check "Заголовки" "Префиксы cookie" "info" "не используются ($pref из $cookieCount)" "Префикс __Host- мешает подменить cookie с поддомена"
    }
}

# контент страницы
if ($body) {
    if ($Url -match '^https') {
        $mixed = ([regex]::Matches($body, '(?i)(?:src|href)\s*=\s*["'']http://')).Count
        if ($mixed -gt 0) {
            Add-Check "Контент" "Смешанный контент" "warn" "$mixed ссылок по http" "Переведите ресурсы на https, браузер их блокирует"
        } else {
            Add-Check "Контент" "Смешанный контент" "pass" "не найден" "не требуется"
        }
    }

    # sri
    $scripts = [regex]::Matches($body, '(?is)<script[^>]+src\s*=\s*["''][^"'']+["''][^>]*>')
    $extCount = 0; $noSri = 0
    foreach ($sc in $scripts) {
        $tag = $sc.Value
        if ($tag -match '(?i)src\s*=\s*["''](https?:)?//') {
            $extCount++
            if ($tag -notmatch '(?i)integrity\s*=') { $noSri++ }
        }
    }
    if ($extCount -gt 0 -and $noSri -gt 0) {
        Add-Check "Контент" "SRI у внешних скриптов" "warn" "$noSri из $extCount без integrity" "Подмена файла на CDN ломает сайт, добавьте integrity и crossorigin"
    } elseif ($extCount -gt 0) {
        Add-Check "Контент" "SRI у внешних скриптов" "pass" "все с integrity" "не требуется"
    } else {
        Add-Check "Контент" "SRI у внешних скриптов" "info" "внешних скриптов нет" "не требуется"
    }

    # tabnabbing
    $blankLinks = [regex]::Matches($body, '(?is)<a\b[^>]*target\s*=\s*["'']_blank["''][^>]*>')
    $badBlank = 0
    foreach ($bl in $blankLinks) {
        if ($bl.Value -notmatch '(?i)rel\s*=\s*["''][^"'']*noopener') { $badBlank++ }
    }
    if ($badBlank -gt 0) {
        Add-Check "Контент" "target=_blank без noopener" "warn" "$badBlank ссылок" "Добавьте rel=noopener noreferrer"
    } elseif ($blankLinks.Count -gt 0) {
        Add-Check "Контент" "target=_blank без noopener" "pass" "все с noopener" "не требуется"
    } else {
        Add-Check "Контент" "target=_blank без noopener" "info" "таких ссылок нет" "не требуется"
    }

    # листинг
    if ($body -match '(?i)<title>\s*index of|directory listing for|\[to parent directory\]') {
        Add-Check "Раскрытие" "Листинг каталога" "warn" "страница похожа на список файлов" "Отключите autoindex на сервере"
    } else {
        Add-Check "Раскрытие" "Листинг каталога" "pass" "не обнаружен" "не требуется"
    }
}

# мягкая 404
$probe = "zz" + ([guid]::NewGuid().ToString("N").Substring(0, 8))
$softFile = Join-Path $tmp "soft.html"
$softCode = & $curl @baseArgs -o $softFile -w "%{http_code}" ($Url + "/" + $probe) 2>$null
$softCode = "$softCode".Trim()
$softBody = ""
if (Test-Path -LiteralPath $softFile) { $softBody = Get-Content -LiteralPath $softFile -Raw -ErrorAction SilentlyContinue }

if ($softCode -eq "200") {
    Add-Check "Раскрытие" "Мягкая 404" "warn" "несуществующий путь отдаёт 200" "Настройте отдачу 404, иначе сканер видит бесконечные страницы"
} else {
    Add-Check "Раскрытие" "Мягкая 404" "pass" "несуществующий путь отдаёт $softCode" "не требуется"
}

# ошибки
$errMarkers = 'Fatal error|Parse error|Warning: |Notice: |stack trace|Traceback \(most recent call last\)|System\.NullReferenceException|ORA-\d{4,}|SQL syntax.*MySQL|SQLSTATE\['
if ($softBody -and $softBody -match $errMarkers) {
    Add-Check "Раскрытие" "Сообщения об ошибках" "fail" "в ответе видны технические подробности" "Отключите вывод ошибок, пишите их в лог"
} else {
    Add-Check "Раскрытие" "Сообщения об ошибках" "pass" "не обнаружены" "не требуется"
}

# trace
$traceCode = & $curl @baseArgs -X TRACE -o NUL -w "%{http_code}" $Url 2>$null
$traceCode = "$traceCode".Trim()
if ($traceCode -eq "200") {
    Add-Check "Методы" "Метод TRACE" "warn" "TRACE включён" "Отключите TRACE, он отдаёт заголовки запроса обратно"
} else {
    Add-Check "Методы" "Метод TRACE" "pass" "TRACE отдаёт $traceCode" "не требуется"
}

# options
$optRaw = & $curl @baseArgs -X OPTIONS -D - -o NUL $Url 2>$null | Out-String
$allowLine = ""
if ($optRaw -match '(?im)^allow:\s*(.+)$') { $allowLine = $Matches[1].Trim() }
if ($allowLine -and $allowLine -match '(?i)\b(PUT|DELETE|PATCH)\b') {
    $badMethod = $Matches[1].ToUpper()
    Add-Check "Методы" "Опасные HTTP-методы" "warn" "разрешён $badMethod" "Если методы не нужны приложению, отключите их"
} elseif ($allowLine) {
    Add-Check "Методы" "Опасные HTTP-методы" "pass" $allowLine "не требуется"
} else {
    Add-Check "Методы" "Опасные HTTP-методы" "info" "сервер не вернул Allow" "не требуется"
}

# редирект http
if ($Url -match '^https') {
    $httpUrl = "http://" + $hostName
    $redirRaw = & $curl @baseArgs -o NUL -w "%{http_code}|%{redirect_url}" $httpUrl 2>$null
    if ($redirRaw) {
        $redirRaw = "$redirRaw".Trim()
        $rcode = ($redirRaw -split '\|')[0]
        $rurl = ""
        if ($redirRaw -match '\|(.+)$') { $rurl = $Matches[1] }
        if ($rcode -in @("301", "302", "307", "308") -and $rurl -match '^https://') {
            Add-Check "Методы" "Редирект с HTTP" "pass" "$rcode на $rurl" "не требуется"
        } elseif ($rcode -eq "200") {
            Add-Check "Методы" "Редирект с HTTP" "warn" "http отдаёт 200 без редиректа" "Настройте 301 на https"
        } elseif ($rcode) {
            Add-Check "Методы" "Редирект с HTTP" "info" "http отдаёт $rcode" "не требуется"
        }
    }
}

# отражение origin
$originProbe = "https://audit.invalid"
$corsRaw = & $curl @baseArgs -H "Origin: $originProbe" -D - -o NUL $Url 2>$null | Out-String
$acaoRef = ""
if ($corsRaw -match '(?im)^access-control-allow-origin:\s*(.+)$') { $acaoRef = $Matches[1].Trim() }
if ($acaoRef -eq $originProbe) {
    Add-Check "Раскрытие" "Отражение Origin в CORS" "fail" "любой Origin попадает в ответ" "Ограничьте список доменов, иначе чужие сайты читают ответы"
} elseif ($acaoRef) {
    Add-Check "Раскрытие" "Отражение Origin в CORS" "pass" "Origin не отражается" "не требуется"
} else {
    Add-Check "Раскрытие" "Отражение Origin в CORS" "pass" "заголовок не отдаётся" "не требуется"
}

# security.txt
$secCode = & $curl @baseArgs -o NUL -w "%{http_code}" ($Url + "/.well-known/security.txt") 2>$null
if ("$secCode".Trim() -eq "200") {
    Add-Check "Контент" "security.txt" "pass" "найден" "не требуется"
} else {
    Add-Check "Контент" "security.txt" "info" "не найден" "Добавьте контакт для сообщений об уязвимостях"
}

# старые tls
function Test-TlsVersion([string]$h, [int]$p, [System.Security.Authentication.SslProtocols]$proto) {
    try {
        $tcp2 = New-Object System.Net.Sockets.TcpClient
        $tcp2.Connect($h, $p)
        $cb2 = [System.Net.Security.RemoteCertificateValidationCallback] { param($a1, $a2, $a3, $a4) $true }
        $ssl2 = New-Object System.Net.Security.SslStream($tcp2.GetStream(), $false, $cb2)
        $ssl2.AuthenticateAsClient($h, $null, $proto, $false)
        $ssl2.Dispose()
        $tcp2.Close()
        return $true
    } catch {
        return $false
    }
}

if ($Url -match '^https' -and -not $certError) {
    $tlsPort = 443
    if (([uri]$Url).Port -gt 0) { $tlsPort = ([uri]$Url).Port }
    $weakTls = @()
    if (Test-TlsVersion $hostName $tlsPort ([System.Security.Authentication.SslProtocols]::Tls)) { $weakTls += "1.0" }
    if (Test-TlsVersion $hostName $tlsPort ([System.Security.Authentication.SslProtocols]::Tls11)) { $weakTls += "1.1" }
    if ($weakTls.Count -gt 0) {
        Add-Check "TLS" "TLS 1.0 и 1.1" "fail" ("включены TLS " + ($weakTls -join " и ")) "Оставьте только 1.2 и 1.3"
    } else {
        Add-Check "TLS" "TLS 1.0 и 1.1" "pass" "отключены" "не требуется"
    }
}

# сводка
$pass = @($checks | Where-Object { $_.Status -eq "pass" }).Count
$warn = @($checks | Where-Object { $_.Status -eq "warn" }).Count
$fail = @($checks | Where-Object { $_.Status -eq "fail" }).Count
$info = @($checks | Where-Object { $_.Status -eq "info" }).Count
$total = $pass + $warn + $fail
$score = 0
if ($total -gt 0) { $score = [int](100 * ($pass + 0.5 * $warn) / $total) }

$sevColor = @{ pass = "#1a7f37"; warn = "#9a6700"; fail = "#cf222e"; info = "#57606a" }
$sevText = @{ pass = "OK"; warn = "ВНИМАНИЕ"; fail = "ПРОБЛЕМА"; info = "ИНФО" }

# счёт по уровням
$crit = 0; $high = 0; $med = 0; $low = 0
foreach ($c in $checks) {
    if ($c.Status -in @("warn", "fail")) {
        $cs = (Get-Cvss $c.Name).s
        if ($cs -ge 9.0) { $crit++ }
        elseif ($cs -ge 7.0) { $high++ }
        elseif ($cs -ge 4.0) { $med++ }
        else { $low++ }
    }
}

# строки таблицы
$rows = ""
$categories = $checks | Group-Object Category
foreach ($g in $categories) {
    $rows += "<h2>" + (HtmlEnc $g.Name) + "</h2><table><tr><th>Проверка</th><th>Статус</th><th>CVSS</th><th>Детали</th><th>Что делать</th></tr>"
    foreach ($c in $g.Group) {
        $col = $sevColor[$c.Status]
        $txt = $sevText[$c.Status]
        $cv = "-"
        $cvTitle = ""
        if ($c.Status -in @("warn", "fail")) {
            $m = Get-Cvss $c.Name
            $sev = Get-Sev $m.s
            $cv = "<span style='color:$($sev.C);font-weight:600'>$($m.s)</span> <span style='color:#57606a;font-size:12px'>$($sev.T)</span>"
            $cvTitle = $m.v
        }
        $rows += "<tr><td class='chk'>" + (HtmlEnc $c.Name) + "</td><td><span class='badge' style='background:$col'>$txt</span></td><td class='cv' title='$cvTitle'>$cv</td><td>" + (HtmlEnc $c.Detail) + "</td><td class='adv'>" + (HtmlEnc $c.Advice) + "</td></tr>"
    }
    $rows += "</table>"
}

# блок ffuf
$ffufSection = ""
if ($ffufRan) {
    $ffufSection = "<h2>Найденные пути (ffuf)</h2>"
    if ($ffufResults.Count -eq 0) {
        $ffufSection += "<p class='muted'>Скрытых путей не найдено.</p>"
    } else {
        $ffufSection += "<table><tr><th>URL</th><th>Код</th><th>Размер</th><th>Слов</th></tr>"
        foreach ($r in $ffufResults) {
            $ffufSection += "<tr><td class='mono'>" + (HtmlEnc $r.url) + "</td><td>" + (HtmlEnc "$($r.status)") + "</td><td>" + (HtmlEnc "$($r.length)") + "</td><td>" + (HtmlEnc "$($r.words)") + "</td></tr>"
        }
        $ffufSection += "</table>"
    }
}

# редиректы
$redirectInfo = ""
if ($redirectChain.Count -gt 1) {
    $parts = @()
    foreach ($r in $redirectChain) { $parts += ("$($r.Code)" + $(if ($r.Location) { " -> " + $r.Location } else { "" })) }
    $redirectInfo = "<p class='muted'>Редиректы: " + (HtmlEnc ($parts -join " | ")) + "</p>"
}

$dateStr = (Get-Date).ToString("dd.MM.yyyy HH:mm")

# время ответа
$timeStr = "$timeTotal"
$parseSeconds = 0.0
$timeClean = "$timeTotal" -replace ',', '.'
if ([double]::TryParse($timeClean, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parseSeconds)) {
    $timeStr = $parseSeconds.ToString("0.00", [System.Globalization.CultureInfo]::InvariantCulture)
}

# блок автора
$authorBlock = "<div class='author'><div><div class='aname'>AquaWayne</div><a href='https://github.com/AquaWayne' target='_blank' rel='noopener'>github.com/AquaWayne</a></div></div>"
if ($avatarB64) {
    $authorBlock = "<div class='author'><img src='data:image/png;base64,$avatarB64' alt='AquaWayne' class='avatar'><div><div class='aname'>AquaWayne</div><a href='https://github.com/AquaWayne' target='_blank' rel='noopener'>github.com/AquaWayne</a></div></div>"
}

$html = @"
<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Аудит безопасности: $(HtmlEnc $hostName)</title>
<style>
:root { --bg:#f6f8fa; --card:#fff; --line:#d0d7de; --text:#1f2328; }
* { box-sizing:border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--text);
  font:15px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif; }
.wrap { max-width:1080px; margin:0 auto; }
header { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px 28px; margin-bottom:20px; }
.head-top { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; flex-wrap:wrap; }
.author { display:flex; align-items:center; gap:12px; }
.avatar { width:52px; height:52px; border-radius:50%; object-fit:cover; border:2px solid var(--line); display:block; }
.aname { font-weight:600; font-size:15px; }
.author a { color:#0969da; text-decoration:none; font-size:13px; }
.author a:hover { text-decoration:underline; }
h1 { margin:0 0 6px; font-size:24px; }
h2 { font-size:18px; margin:28px 0 10px; }
.muted { color:#57606a; font-size:13px; }
.score { display:flex; align-items:center; gap:20px; margin-top:16px; flex-wrap:wrap; }
.num { font-size:44px; font-weight:700; line-height:1; }
.bar { flex:1; min-width:220px; height:10px; background:#eaeef2; border-radius:6px; overflow:hidden; display:flex; }
.bar span { display:block; height:100%; }
.legend { display:flex; gap:16px; font-size:13px; color:#57606a; flex-wrap:wrap; }
.legend b { color:var(--text); }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
  border-radius:8px; overflow:hidden; font-size:14px; }
th { background:#f6f8fa; text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); font-weight:600; }
td { padding:10px 12px; border-bottom:1px solid #eaeef2; vertical-align:top; }
tr:last-child td { border-bottom:none; }
.badge { color:#fff; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:700; white-space:nowrap; }
.chk { font-weight:500; width:20%; }
.cv { width:11%; font-size:13px; white-space:nowrap; }
.adv { color:#57606a; width:28%; font-size:13px; }
.mono { font-family:Consolas,monospace; font-size:13px; }
.note { background:#fff8c5; border:1px solid #d4a72c; border-radius:8px; padding:16px 20px; margin-top:24px; font-size:14px; }
.note h3 { margin:0 0 8px; font-size:15px; }
.note ul { margin:8px 0 0; padding-left:20px; }
footer { text-align:center; color:#57606a; font-size:12px; margin:28px 0 8px; }
@media print { body { background:#fff; padding:0; } table { page-break-inside:auto; } tr { page-break-inside:avoid; } }
</style></head><body><div class="wrap">
<header>
  <div class="head-top">
    <div>
      <h1>Аудит безопасности: $(HtmlEnc $hostName)</h1>
      <div class="muted">$(HtmlEnc $Url) &nbsp;•&nbsp; $(HtmlEnc $dateStr) &nbsp;•&nbsp; код ответа $(HtmlEnc $status) &nbsp;•&nbsp; $(HtmlEnc $timeStr) c</div>
    </div>
    $authorBlock
  </div>
  $redirectInfo
  <div class="score">
    <div class="num" style="color:$(if($score -ge 80){'#1a7f37'}elseif($score -ge 50){'#9a6700'}else{'#cf222e'})">$score<span style="font-size:18px;font-weight:400">/100</span></div>
    <div style="flex:1;min-width:220px">
      <div class="bar">
        <span style="width:$(if($total -gt 0){[int](100*$pass/$total)}else{0})%;background:#1a7f37"></span>
        <span style="width:$(if($total -gt 0){[int](100*$warn/$total)}else{0})%;background:#d4a72c"></span>
        <span style="width:$(if($total -gt 0){[int](100*$fail/$total)}else{0})%;background:#cf222e"></span>
      </div>
      <div class="legend" style="margin-top:8px">
        <span>Пройдено: <b>$pass</b></span>
        <span>Внимание: <b>$warn</b></span>
        <span>Проблем: <b>$fail</b></span>
        <span>Инфо: <b>$info</b></span>
      </div>
      <div class="legend" style="margin-top:4px">
        <span>Критично: <b style="color:#a40e26">$crit</b></span>
        <span>Высоко: <b style="color:#cf222e">$high</b></span>
        <span>Средне: <b style="color:#bf8700">$med</b></span>
        <span>Низко: <b>$low</b></span>
      </div>
    </div>
  </div>
</header>
$rows
$ffufSection
<div class="note">
  <h3>Что этот отчёт не проверяет и почему</h3>
  <ul>
    <li><b>Нагрузка и отказ в обслуживании.</b> Проверка «упадёт ли сайт» является атакой, а не тестом: страдает хостинг, соседние сайты на том же сервере и репутация. Нагрузочное тестирование делают отдельно (k6, Locust) на тестовом контуре, с потолком «ожидаемый пик плюс запас», и целью ставят не падение, а устойчивость.</li>
    <li><b>Инъекции (SQLi, XSS, RCE).</b> Нужны специализированные инструменты (sqlmap, nuclei) и копия сайта либо согласованный пентест. Этот скрипт делает один запрос на проверку и ничего не ломает.</li>
    <li><b>Выгрузка базы (ФИО, телефоны).</b> Не выполняется, это утечка персональных данных. Если база ваша, берите бэкап, а не выгружайте её через уязвимость. Для подтверждения SQLi достаточно запроса вроде @@version.</li>
    <li><b>Массовое создание аккаунтов, обход регистрации по телефону и рассылка писем.</b> Не выполняется: письма уйдут реальным людям, домен попадёт в спам-листы, восстановление репутации занимает недели. Проверяется вручную: captcha, подтверждение почты и номера, лимиты попыток, срок жизни кода.</li>
    <li><b>Эксплуатация уязвимостей.</b> Скрипт не подбирает пароли, не перебирает одноразовые коды и не запускает эксплойты. Для этого нужен согласованный пентест на копии сайта, а не автоматический прогон по боевому адресу.</li>
  </ul>
</div>
<footer>Пассивная проверка: $(HtmlEnc $checks.Count) $(Plural $checks.Count "пункт" "пункта" "пунктов"), $(HtmlEnc $redirects) $(Plural $redirects "редирект" "редиректа" "редиректов"). CVSS: ориентировочные оценки v3.1. Отчёт: audit.ps1, автор AquaWayne. Перебор путей: ffuf, автор Joona Hoikkala, MIT.</footer>
</div></body></html>
"@

$htmlPath = Join-Path (Get-Location) $Out
if (-not [System.IO.Path]::IsPathRooted($Out)) { $htmlPath = Join-Path (Get-Location) $Out }
[System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

# csv для трекера
if ($Csv) {
    $cweMap = @{
        "Strict-Transport-Security (HSTS)" = "CWE-319"
        "X-Frame-Options"                  = "CWE-1021"
        "CSP frame-ancestors"              = "CWE-1021"
        "Content-Security-Policy"          = "CWE-693"
        "CSP unsafe-eval"                  = "CWE-693"
        "X-Content-Type-Options"           = "CWE-436"
        "Referrer-Policy"                  = "CWE-200"
        "Permissions-Policy"               = "CWE-16"
        "Cross-Origin-Opener-Policy"       = "CWE-346"
        "Cross-Origin-Embedder-Policy"     = "CWE-346"
        "Cross-Origin-Resource-Policy"     = "CWE-346"
        "X-Permitted-Cross-Domain-Policies" = "CWE-16"
        "HSTS preload"                     = "CWE-319"
        "Префиксы cookie"                  = "CWE-565"
        "Флаги cookie"                     = "CWE-614"
        "Заголовок Server"                 = "CWE-200"
        "Заголовок X-Powered-By"           = "CWE-200"
        "CORS"                             = "CWE-942"
        "Отражение Origin в CORS"          = "CWE-942"
        "HTTPS"                            = "CWE-319"
        "Сертификат"                       = "CWE-295"
        "Цепочка сертификата"              = "CWE-295"
        "Срок действия"                    = "CWE-298"
        "Версия протокола"                 = "CWE-327"
        "TLS 1.0 и 1.1"                    = "CWE-327"
        "Git-репозиторий"                  = "CWE-538"
        ".env с секретами"                 = "CWE-798"
        "SVN-метаданные"                   = "CWE-538"
        "Архив бэкапа"                     = "CWE-530"
        "Дамп БД"                          = "CWE-530"
        "phpinfo()"                        = "CWE-200"
        "Apache server-status"             = "CWE-200"
        "Бэкап конфига WordPress"          = "CWE-538"
        "robots.txt"                       = "CWE-200"
        "Листинг каталога"                 = "CWE-548"
        "Мягкая 404"                       = "CWE-756"
        "Сообщения об ошибках"             = "CWE-209"
        "Captcha на форме входа"           = "CWE-307"
        "CSRF-токен в формах"              = "CWE-352"
        "Поле телефона"                    = "CWE-307"
        "Автозаполнение паролей"           = "CWE-522"
        "SPF"                              = "CWE-290"
        "DMARC"                            = "CWE-290"
        "Метод TRACE"                      = "CWE-749"
        "Опасные HTTP-методы"              = "CWE-650"
        "Редирект с HTTP"                  = "CWE-319"
        "Смешанный контент"                = "CWE-311"
        "SRI у внешних скриптов"           = "CWE-353"
        "target=_blank без noopener"       = "CWE-1022"
        "security.txt"                     = "CWE-1059"
        "Перебор путей (ffuf)"             = "CWE-200"
    }

    # экранирование ячейки
    function CsvCell([string]$v) {
        if ($null -eq $v) { $v = "" }
        $v = $v -replace '"', '""'
        if ($v -match '[;"\r\n]') { return '"' + $v + '"' }
        return $v
    }

    # сортировка по риску
    $csvChecks = @($checks | Sort-Object -Property @(
        @{ Expression = { if ($_.Status -in @("warn", "fail")) { 0 } elseif ($_.Status -eq "info") { 2 } else { 3 } } },
        @{ Expression = { if ($_.Status -in @("warn", "fail")) { -(Get-Cvss $_.Name).s } else { 0 } } }
    ))

    $lines = @()
    $lines += (@("ID", "Приоритет", "Категория", "Проверка", "Статус", "Уровень", "CVSS", "Вектор", "CWE", "CVE", "Детали", "Рекомендация", "URL") -join $CsvDelimiter)

    $n = 0
    foreach ($c in $csvChecks) {
        $n++
        $id = "AUD-{0:D3}" -f $n
        $level = ""
        $cvssVal = ""
        $vector = ""
        $prio = "P4"
        if ($c.Status -in @("warn", "fail")) {
            $m = Get-Cvss $c.Name
            $sev = Get-Sev $m.s
            $level = $sev.T
            $cvssVal = $m.s
            $vector = $m.v
            if ($m.s -ge 9.0) { $prio = "P1" }
            elseif ($m.s -ge 7.0) { $prio = "P2" }
            elseif ($m.s -ge 4.0) { $prio = "P3" }
        } elseif ($c.Status -eq "info") {
            $level = "Инфо"
            $prio = "-"
        } else {
            $level = "Нет"
            $prio = "-"
        }

        $cwe = "CWE-16"
        if ($cweMap.ContainsKey($c.Name)) { $cwe = $cweMap[$c.Name] }

        $cells = @(
            $id, $prio, $c.Category, $c.Name, $c.Status, $level, $cvssVal, $vector,
            $cwe, "", $c.Detail, $c.Advice, $Url
        ) | ForEach-Object { CsvCell ([string]$_) }

        $lines += ($cells -join $CsvDelimiter)
    }

    $csvPath = [System.IO.Path]::ChangeExtension($htmlPath, ".csv")
    [System.IO.File]::WriteAllText($csvPath, ($lines -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
}

Write-Host ""
Write-Host "OK: $pass | Внимание: $warn | Проблем: $fail | Оценка: $score/100" -ForegroundColor Cyan
Write-Host "Критично: $crit | Высоко: $high | Средне: $med | Низко: $low" -ForegroundColor Yellow
Write-Host "Отчёт: $htmlPath" -ForegroundColor Green
if ($Csv) { Write-Host "CSV: $csvPath" -ForegroundColor Green }
