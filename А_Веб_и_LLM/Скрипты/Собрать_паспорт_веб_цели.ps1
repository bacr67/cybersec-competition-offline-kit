[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][uri]$Uri,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$RunNmap,
    [switch]$ConfirmAuthorizedScope,
    [string]$NmapPath
)

$ErrorActionPreference = 'Stop'
if ($Uri.Scheme -notin @('http','https') -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment -or $Uri.AbsolutePath -ne '/') {
    throw 'Укажи базовый URL вида https://host/ без логина, пароля, пути приложения, query и fragment.'
}
if ($RunNmap -and -not $ConfirmAuthorizedScope) {
    throw 'Перед активным сканированием добавь -ConfirmAuthorizedScope после проверки IP/домена и правил соревнования.'
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $outputRoot)) { New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null }
$outputRoot = (Resolve-Path -LiteralPath $outputRoot).Path
$runPath = Join-Path $outputRoot ('Веб_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $runPath -Force | Out-Null

$targets = @(
    [pscustomobject]@{ Path='/'; Purpose='Главная страница' },
    [pscustomobject]@{ Path='/robots.txt'; Purpose='Правила индексации' },
    [pscustomobject]@{ Path='/sitemap.xml'; Purpose='Карта сайта' },
    [pscustomobject]@{ Path='/.well-known/security.txt'; Purpose='Контакт security.txt' }
)
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $true
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(12)
$rows = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($target in $targets) {
        $requestUri = [uri]::new($Uri, $target.Path)
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $requestUri)
        $response = $null
        $errorText = ''
        try {
            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $headers = @{}
            foreach ($header in $response.Headers) { $headers[$header.Key.ToLowerInvariant()] = ($header.Value -join ', ') }
            foreach ($header in $response.Content.Headers) { $headers[$header.Key.ToLowerInvariant()] = ($header.Value -join ', ') }
            $rows.Add([pscustomobject]@{
                Путь=$target.Path; Назначение=$target.Purpose; Статус=[int]$response.StatusCode
                КонечныйURL=[string]$response.RequestMessage.RequestUri
                ТипСодержимого=[string]$response.Content.Headers.ContentType
                РазмерОтветаБайт=if($response.Content.Headers.ContentLength){[long]$response.Content.Headers.ContentLength}else{''}
                Сервер=$headers['server']; XPoweredBy=$headers['x-powered-by']
                HSTS=[bool]$headers.ContainsKey('strict-transport-security')
                CSP=[bool]$headers.ContainsKey('content-security-policy')
                XContentTypeOptions=[bool]$headers.ContainsKey('x-content-type-options')
                XFrameOptions=[bool]$headers.ContainsKey('x-frame-options')
                ReferrerPolicy=[bool]$headers.ContainsKey('referrer-policy')
                PermissionsPolicy=[bool]$headers.ContainsKey('permissions-policy')
                Ошибка=''
            })
        }
        catch {
            $errorText = $_.Exception.GetBaseException().Message
            $rows.Add([pscustomobject]@{Путь=$target.Path;Назначение=$target.Purpose;Статус='';КонечныйURL='';ТипСодержимого='';РазмерОтветаБайт='';Сервер='';XPoweredBy='';HSTS=$false;CSP=$false;XContentTypeOptions=$false;XFrameOptions=$false;ReferrerPolicy=$false;PermissionsPolicy=$false;Ошибка=$errorText})
        }
        finally { if($response){$response.Dispose()};$request.Dispose() }
    }
}
finally { $client.Dispose(); $handler.Dispose() }

$rows | Export-Csv -LiteralPath (Join-Path $runPath 'HTTP_проверки.csv') -NoTypeInformation -Encoding UTF8
$dns = try { @([Net.Dns]::GetHostAddresses($Uri.DnsSafeHost) | ForEach-Object { $_.IPAddressToString }) -join ', ' } catch { 'Не удалось разрешить DNS: ' + $_.Exception.GetBaseException().Message }
$nmapStatus = 'Не запускался'
if ($RunNmap) {
    if (-not $NmapPath) {
        $nmapCommand = Get-Command nmap.exe -ErrorAction SilentlyContinue
        if ($nmapCommand) { $NmapPath = $nmapCommand.Source }
        else { throw 'Nmap не найден. Установи его из папки Инструменты или передай -NmapPath.' }
    }
    if (-not (Test-Path -LiteralPath $NmapPath -PathType Leaf)) { throw "Nmap не найден: $NmapPath" }
    $nmapBase = Join-Path $runPath 'Nmap_версии_и_популярные_порты'
    $nmapArgs = @('-Pn','-n','-sV','--top-ports','1000','-oA',$nmapBase,$Uri.DnsSafeHost)
    & $NmapPath @nmapArgs 2>&1 | Set-Content -LiteralPath (Join-Path $runPath 'Nmap_вывод.txt') -Encoding UTF8
    $nmapStatus = "Завершён, код $LASTEXITCODE; аргументы: $($nmapArgs -join ' ')"
}

$lines = @(
    '# Первичный паспорт веб-цели','',
    "- Сформировано UTC: $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))",
    "- Базовый URL: $($Uri.GetLeftPart([UriPartial]::Authority))$($Uri.AbsolutePath)",
    "- DNS: $dns",
    "- Nmap: $nmapStatus",
    '- Режим HTTP: только GET на главную, robots.txt, sitemap.xml и security.txt; тело ответа не сохраняется.','',
    '## Что проверить вручную','',
    '1. Сверь домен/IP и разрешённый scope до любых дополнительных запросов.',
    '2. Проверь отсутствующие security headers по контексту приложения. Их отсутствие само по себе не доказывает exploitable-уязвимость.',
    '3. Изучи редиректы, версии и пути вручную; не доверяй одному HTTP-заголовку как подтверждению версии ПО.',
    '4. Продолжай тесты авторизации, IDOR, API, инъекций и LLM только в разрешённом стенде.',
    '5. Сохраняй запрос/ответ, роль, время, точный endpoint, фактический и ожидаемый результат.'
)
$lines | Set-Content -LiteralPath (Join-Path $runPath 'Паспорт_веб_цели.md') -Encoding UTF8
Write-Host "Результаты сохранены: $runPath"
Write-Host "Проверено HTTP-путей: $($rows.Count); DNS: $dns; Nmap: $nmapStatus"
