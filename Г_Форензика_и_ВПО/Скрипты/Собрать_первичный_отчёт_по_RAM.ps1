[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MemoryPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$PythonExe,
    [switch]$AllowSymbolDownload
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
$pluginNames = @('windows.info','windows.pslist','windows.psscan','windows.netscan','windows.cmdline','windows.malware.malfind','windows.dlllist')
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
    '4. `windows.cmdline`: проверьте аргументы, временные каталоги, кодирование и родительский контекст.',
    '5. `windows.malware.malfind`: рассматривайте найденные области как кандидаты; подтвердите их через процесс, модули, сеть и дампы.',
    '6. Сопоставьте PID с `windows.dlllist`, журналами, Prefetch/Amcache и образом диска. Не запускайте извлечённые файлы.',
    '',
    '## Ограничения','',
    'Плагин с ненулевым кодом не дал подтверждённого результата: прочитайте его `.txt`, проверьте формат дампа и доступность Windows symbols. Скрипт не определяет компрометацию автоматически; пустой вывод не доказывает чистоту памяти.',
    $(if ($offlineSymbolFailure) { 'Для этого запуска улики из перечисленных выше плагинов не получены: Volatility не смогла разрешить символы ядра в офлайн-режиме.' })
)
$report | Set-Content -LiteralPath (Join-Path $run 'Первичный_отчёт_RAM.md') -Encoding UTF8
Write-Host "Первичный отчёт RAM: $(Join-Path $run 'Первичный_отчёт_RAM.md')"
Write-Host "SHA-256 дампа: $hash; выводы плагинов: $($results.Count); среда Volatility: $environment"
