[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MemoryPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$PythonExe,
    [switch]$AllowSymbolDownload,
    [switch]$ScanMemoryStrings
)

$ErrorActionPreference = 'Stop'
$memory = (Resolve-Path -LiteralPath $MemoryPath).Path
$memoryItem = Get-Item -LiteralPath $memory
if ($memoryItem.PSIsContainer) { throw 'Укажи файл дампа памяти, например .raw, .mem, .dmp или .vmem.' }
$outputBase = [IO.Path]::GetFullPath($OutputRoot)
$sourceDirectory = $memoryItem.DirectoryName.TrimEnd('\')
if ($outputBase.TrimEnd('\').Equals($sourceDirectory,[StringComparison]::OrdinalIgnoreCase) -or
    $outputBase.StartsWith($sourceDirectory + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Результаты должны находиться вне папки с исходным дампом.'
}
if (-not (Test-Path -LiteralPath $outputBase)) { New-Item -ItemType Directory -Path $outputBase -Force | Out-Null }
$outputBase = (Resolve-Path -LiteralPath $outputBase).Path
$run = Join-Path $outputBase ('RAM_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $run -Force | Out-Null

$toolsRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\Инструменты')).Path
$wheelhouse = Join-Path $toolsRoot 'Volatility3-wheelhouse'
$pythonArgsPrefix = @()
if ($PythonExe) {
    if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "Не найден Python: $PythonExe" }
}
else {
    $candidate = Get-Command python3.exe,python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        $PythonExe = $candidate.Source
        $versionText = & $PythonExe --version 2>&1 | Out-String
        if ($versionText -notmatch 'Python 3\.') { $PythonExe = $null }
    }
    if (-not $PythonExe) {
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $PythonExe = $launcher.Source
            $pythonArgsPrefix = @('-3')
            $versionText = & $PythonExe @pythonArgsPrefix --version 2>&1 | Out-String
            if ($versionText -notmatch 'Python 3\.') { $PythonExe = $null }
        }
    }
    if (-not $PythonExe) {
        $installer = Join-Path $toolsRoot 'python-3.13.17-amd64.exe'
        throw "Python 3 не найден. Офлайн-установщик в комплекте: $installer. Установи Python 3, затем повтори запуск."
    }
}

$environment = Join-Path $outputBase 'Среда_Volatility3'
$venvPython = Join-Path $environment 'Scripts\python.exe'
$volatility = Join-Path $environment 'Scripts\vol.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    & $PythonExe @pythonArgsPrefix -m venv $environment
    if ($LASTEXITCODE -ne 0) { throw "Не удалось создать виртуальную среду Python, код $LASTEXITCODE." }
}
if (-not (Test-Path -LiteralPath $volatility)) {
    & $venvPython -m pip install --no-index --find-links $wheelhouse 'volatility3==2.28.2'
    if ($LASTEXITCODE -ne 0) { throw "Не удалось установить Volatility из локального wheelhouse, код $LASTEXITCODE. Проверь оба .whl файла." }
}

$hash = (Get-FileHash -LiteralPath $memory -Algorithm SHA256).Hash
$pluginNames = @('windows.info','windows.pslist','windows.psscan','windows.malware.psxview','windows.netscan','windows.cmdline','windows.malware.malfind','windows.ldrmodules','windows.svcscan','windows.registry.hivelist','windows.dlllist','windows.filescan','windows.handles')
$results = [System.Collections.Generic.List[object]]::new()
 $previousPythonIoEncoding = $env:PYTHONIOENCODING
try {
    $env:PYTHONIOENCODING = 'utf-8'
    foreach ($plugin in $pluginNames) {
        $safeName = $plugin.Replace('.','_')
        $outputFile = Join-Path $run ($safeName + '.txt')
        $arguments = @('-f',$memory)
        if (-not $AllowSymbolDownload) { $arguments += '--offline' }
        $arguments += $plugin
        try {
            & $volatility @arguments 2>&1 | Where-Object { $_ -notmatch '^Progress:' } | Set-Content -LiteralPath $outputFile -Encoding UTF8
            $code = $LASTEXITCODE
            $results.Add([pscustomobject]@{ Plugin=$plugin; ExitCode=$code; File=[IO.Path]::GetFileName($outputFile) })
        }
        catch {
            $_ | Out-String | Set-Content -LiteralPath $outputFile -Encoding UTF8
            $results.Add([pscustomobject]@{ Plugin=$plugin; ExitCode=9009; File=[IO.Path]::GetFileName($outputFile) })
        }
    }
}
finally {
    if ($null -eq $previousPythonIoEncoding) { Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue }
    else { $env:PYTHONIOENCODING = $previousPythonIoEncoding }
}
$results | Export-Csv -LiteralPath (Join-Path $run 'Результаты_плагинов.csv') -NoTypeInformation -Encoding UTF8

$symbolFailures = @($results | Where-Object { $_.ExitCode -ne 0 } | ForEach-Object {
    $pluginOutput = Get-Content -LiteralPath (Join-Path $run $_.File) -Raw -ErrorAction SilentlyContinue
    if ($pluginOutput -match '(?i)OfflineException|Unable to validate the plugin requirements|Unsatisfied requirement .*symbol_table_name') {
        $_.Plugin
    }
})
$offlineSymbolFailure = (-not $AllowSymbolDownload) -and ($symbolFailures.Count -gt 0)
$symbolNote = if ($offlineSymbolFailure) {
    "Часть плагинов не получила символы ядра в офлайн-режиме ($($symbolFailures -join ', ')). Результаты этих плагинов не получены; это не вывод о чистоте или заражении."
} elseif ($AllowSymbolDownload) {
    'Разрешена попытка получить символы из интернета. Проверьте коды завершения плагинов и наличие сетевого доступа.'
} else {
    'Включён --offline; сетевые загрузки отключены.'
}
$malfindFile = Join-Path $run 'windows_malware_malfind.txt'
$netscanFile = Join-Path $run 'windows_netscan.txt'
$automaticCandidates = [System.Collections.Generic.List[string]]::new()
if (Test-Path -LiteralPath $malfindFile) {
    foreach ($line in (Get-Content -LiteralPath $malfindFile | Where-Object { $_ -match 'PAGE_EXECUTE_READWRITE|MZ header' })) {
        $automaticCandidates.Add("- ``malfind``: ``$line`` — область требует проверки и сама по себе не доказывает внедрение или вредоносность.")
    }
}
if (Test-Path -LiteralPath $netscanFile) {
    foreach ($line in (Get-Content -LiteralPath $netscanFile | Where-Object { $_ -match '^\S+\s+TCPv[46]\s+' })) {
        $fields = $line.Trim() -split '\s+'
        if ($fields.Count -lt 11) { continue }
        $foreignIp = $null
        if (-not [System.Net.IPAddress]::TryParse($fields[4], [ref]$foreignIp) -or $foreignIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
        $octets = $foreignIp.GetAddressBytes()
        $privateOrSpecial = ($octets[0] -eq 0) -or ($octets[0] -eq 10) -or ($octets[0] -eq 127) -or
            ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
            ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
            ($octets[0] -eq 192 -and $octets[1] -eq 168) -or ($octets[0] -ge 224)
        if (-not $privateOrSpecial) {
            $automaticCandidates.Add("- ``netscan``: ``$($fields[1]) $($fields[2]):$($fields[3]) -> $($fields[4]):$($fields[5]), $($fields[6]), PID $($fields[7]) ($($fields[8])), $($fields[9]) $($fields[10])`` — внешний адрес-кандидат; состояние/владелец требуют контекстной проверки.")
        }
    }
}
$stringScanPath = Join-Path $run 'Кандидаты_URL_PHP.txt'
$stringScanNote = 'Не запускался. Для поиска URL в строках дампа добавь параметр -ScanMemoryStrings.'
if ($ScanMemoryStrings) {
    $stringRegex = [regex]::new('https?://[^\s"''<>\x00]{1,500}\.php(?:\?[^\s"''<>\x00]{0,300})?', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $cleanUrlRegex = [regex]::new('^https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~!$&''()*+,;=:@%/?#-]*)?\.php(?:\?[A-Za-z0-9._~!$&''()*+,;=:@%/?#-]*)?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $seenStrings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stringHits = [System.Collections.Generic.List[string]]::new()
    $stream = [System.IO.File]::Open($memory, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] (4MB)
        $chunkStart = [long]0
        $tailAscii = ''
        $tailWide = ''
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $ascii = [System.Text.Encoding]::Latin1.GetString($buffer, 0, $read)
            $wideLength = $read - ($read % 2)
            $wide = [System.Text.Encoding]::Unicode.GetString($buffer, 0, $wideLength)
            foreach ($encoding in @('ASCII','UTF16LE')) {
                if ($encoding -eq 'ASCII') {
                    $textChunk = $tailAscii + $ascii
                    $baseOffset = $chunkStart - $tailAscii.Length
                } else {
                    $textChunk = $tailWide + $wide
                    $baseOffset = $chunkStart - ($tailWide.Length * 2)
                }
                foreach ($match in $stringRegex.Matches($textChunk)) {
                    $offset = if ($encoding -eq 'ASCII') { $baseOffset + $match.Index } else { $baseOffset + ($match.Index * 2) }
                    $value = $match.Value.TrimEnd('.',',',';',')',']','}')
                    if (-not $cleanUrlRegex.IsMatch($value)) { continue }
                    $key = "$encoding|$offset|$value"
                    if ($seenStrings.Add($key)) { $stringHits.Add("$encoding`t0x$('{0:X}' -f $offset)`t$value") }
                }
                if ($encoding -eq 'ASCII') { $tailAscii = $textChunk.Substring([Math]::Max(0, $textChunk.Length - 1024)) }
                else { $tailWide = $textChunk.Substring([Math]::Max(0, $textChunk.Length - 512)) }
            }
            $chunkStart += $read
        }
    }
    finally { $stream.Dispose() }
    @('Кодировка`tСмещение`tКандидат URL PHP', ($stringHits | Sort-Object -Unique)) | Set-Content -LiteralPath $stringScanPath -Encoding UTF8
    $stringScanNote = if ($stringHits.Count -gt 0) { "$($stringHits.Count) строк-кандидатов записано: $stringScanPath. Нужна ручная проверка контекста и процесса." } else { "Строк URL с .php не найдено; поиск был только по ASCII и UTF-16LE: $stringScanPath. Отсутствие строки не доказывает, что URL не посещался." }
    foreach ($group in ($stringHits | ForEach-Object { $parts = $_ -split "`t",3; if ($parts.Count -eq 3) { $parts[2] } } | Group-Object)) {
        $automaticCandidates.Add("- URL `.php` из строк RAM: ``$($group.Name)`` — найдено совпадений: $($group.Count); скрипт не связывает строку автоматически с PID или фактом посещения.")
    }
}
$pythonVersion = (& $PythonExe @pythonArgsPrefix --version 2>&1 | Out-String).Trim()
$report = @(
    '# Первичный отчёт по дампу памяти','',
    "- Файл: ``$memory``",
    "- Размер: $($memoryItem.Length) байт",
    "- SHA-256: $hash",
    "- Дата формирования UTC: $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))",
    "- Python: $pythonVersion",
    '- Volatility 3, версия 2.28.2 из локального wheelhouse.',
    "- Символы: $symbolNote",
    $(if ($offlineSymbolFailure) { '- Следующая попытка: повторите этот же скрипт с параметром `-AllowSymbolDownload`, только если сеть доступна и загрузка символов разрешена.' }),
    "- Поиск URL `.php`: $stringScanNote",
    '- Исходный дамп не изменялся. Каждый вывод плагина сохранён отдельно.','',
    '## Плагины','',
    '| Плагин | Код завершения | Файл вывода |','|---|---:|---|',
    ($results | ForEach-Object { "| $($_.Plugin) | $($_.ExitCode) | ``$($_.File)`` |" }),
    '',
    '## Автоматически отмеченные кандидаты','',
    $(if ($automaticCandidates.Count -gt 0) { $automaticCandidates } else { 'Совпадений простых эвристик по исполняемым областям и внешним TCP-соединениям не найдено. Это не доказывает чистоту памяти.' }),
    '',
    '## Порядок ручного просмотра','',
    '1. `windows.info`: проверьте ОС, архитектуру и время снимка; ошибка символов может мешать определению профиля.',
    '2. Сопоставьте `windows.pslist` и `windows.psscan`; различия требуют проверки, но не доказывают сокрытие процесса.',
    '3. `windows.netscan`: свяжите адреса/порты с PID и временем, если эти сведения доступны.',
    '4. `windows.malware.psxview` сопоставляет способы обнаружения процессов; различия — повод проверить память объекта и родительскую цепочку.',
    '5. `windows.cmdline`: проверьте аргументы, временные каталоги, кодирование и родительский контекст.',
    '6. `windows.malware.malfind` и `windows.ldrmodules`: рассматривайте аномалии как кандидаты; подтвердите их через процесс, модули, сеть и дампы.',
    '7. `windows.svcscan` и `windows.registry.hivelist` добавляют контекст служб и загруженных кустов реестра; сопоставьте их с образом диска и журналами.',
    '8. `windows.filescan` ищет объекты файлов в памяти, а `windows.handles` показывает открытые процессами объекты; используйте их для подтверждения полного пути и владельца.',
    '9. Сопоставьте PID с `windows.dlllist`, журналами, Prefetch/Amcache и образом диска. Не запускайте извлечённые файлы.',
    '10. `-ScanMemoryStrings` включает потоковый поиск URL `.php` в ASCII и UTF-16LE строках; результаты являются подсказками и не привязаны автоматически к PID.',
    '',
    '## Ограничения','',
    'Плагин с ненулевым кодом не дал подтверждённого результата: прочитайте его `.txt`, проверьте формат дампа и доступность Windows symbols. Скрипт не определяет компрометацию автоматически; пустой вывод не доказывает чистоту памяти.',
    $(if ($offlineSymbolFailure) { 'Для этого запуска улики из перечисленных выше плагинов не получены: Volatility не смогла разрешить символы ядра в офлайн-режиме.' })
)
$report | Set-Content -LiteralPath (Join-Path $run 'Первичный_отчёт_RAM.md') -Encoding UTF8
Write-Host "Первичный отчёт RAM: $(Join-Path $run 'Первичный_отчёт_RAM.md')"
Write-Host "SHA-256 дампа: $hash; выводы плагинов: $($results.Count); среда Volatility: $environment"
