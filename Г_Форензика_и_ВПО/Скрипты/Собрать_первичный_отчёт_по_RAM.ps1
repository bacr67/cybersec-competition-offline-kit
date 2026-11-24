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
$pluginNames = @('windows.info','windows.pslist','windows.psscan','windows.netscan','windows.cmdline','windows.malfind','windows.dlllist')
$results = [System.Collections.Generic.List[object]]::new()
foreach ($plugin in $pluginNames) {
    $safeName = $plugin.Replace('.','_')
    $outputFile = Join-Path $run ($safeName + '.txt')
    $arguments = @('-f',$memory)
    if (-not $AllowSymbolDownload) { $arguments += '--offline' }
    $arguments += $plugin
    try {
        & $volatility @arguments 2>&1 | Set-Content -LiteralPath $outputFile -Encoding UTF8
        $code = $LASTEXITCODE
        $results.Add([pscustomobject]@{ Plugin=$plugin; ExitCode=$code; File=[IO.Path]::GetFileName($outputFile) })
    }
    catch {
        $_ | Out-String | Set-Content -LiteralPath $outputFile -Encoding UTF8
        $results.Add([pscustomobject]@{ Plugin=$plugin; ExitCode=9009; File=[IO.Path]::GetFileName($outputFile) })
    }
}
$results | Export-Csv -LiteralPath (Join-Path $run 'Результаты_плагинов.csv') -NoTypeInformation -Encoding UTF8

$symbolNote = if ($AllowSymbolDownload) { 'Разрешена попытка получить символы из интернета. Повторяйте только при допустимом доступе к сети.' } else { 'Включён --offline: скрипт не пытается скачивать символы. При ошибках символов повторите с -AllowSymbolDownload только если сеть разрешена.' }
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
    '- Исходный дамп не изменялся. Каждый вывод плагина сохранён отдельно.','',
    '## Плагины','',
    '| Плагин | Код завершения | Файл вывода |','|---|---:|---|',
    ($results | ForEach-Object { "| $($_.Plugin) | $($_.ExitCode) | ``$($_.File)`` |" }),
    '',
    '## Порядок ручного просмотра','',
    '1. `windows.info`: проверьте ОС, архитектуру и время снимка; ошибка символов может мешать определению профиля.',
    '2. Сопоставьте `windows.pslist` и `windows.psscan`; различия требуют проверки, но не доказывают сокрытие процесса.',
    '3. `windows.netscan`: свяжите адреса/порты с PID и временем, если эти сведения доступны.',
    '4. `windows.cmdline`: проверьте аргументы, временные каталоги, кодирование и родительский контекст.',
    '5. `windows.malfind`: рассматривайте найденные области как кандидаты; подтвердите их через процесс, модули, сеть и дампы.',
    '6. Сопоставьте PID с `windows.dlllist`, журналами, Prefetch/Amcache и образом диска. Не запускайте извлечённые файлы.',
    '',
    '## Ограничения','',
    'Плагин с ненулевым кодом не дал подтверждённого результата: прочитайте его `.txt`, проверьте формат дампа и доступность Windows symbols. Скрипт не определяет компрометацию автоматически; пустой вывод не доказывает чистоту памяти.'
)
$report | Set-Content -LiteralPath (Join-Path $run 'Первичный_отчёт_RAM.md') -Encoding UTF8
Write-Host "Первичный отчёт RAM: $(Join-Path $run 'Первичный_отчёт_RAM.md')"
Write-Host "SHA-256 дампа: $hash; выводы плагинов: $($results.Count); среда Volatility: $environment"
