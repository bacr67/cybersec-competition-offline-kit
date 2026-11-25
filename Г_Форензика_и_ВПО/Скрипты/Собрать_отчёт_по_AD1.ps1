[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ImagePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$PythonPath,

    [switch]$ListOnly
)

$ErrorActionPreference = 'Stop'

$resolvedImages = @($ImagePath | ForEach-Object { (Resolve-Path -LiteralPath $_).Path })
if ($resolvedImages.Count -eq 1) {
    $first = Get-Item -LiteralPath $resolvedImages[0]
    if ($first.PSIsContainer -or $first.Extension -notmatch '^\.ad1$') {
        throw 'Укажи первый сегмент с расширением .ad1. Для других форматов этот сценарий не подходит.'
    }
    $base = [System.IO.Path]::Combine($first.DirectoryName, [System.IO.Path]::GetFileNameWithoutExtension($first.Name))
    $segments = [System.Collections.Generic.List[string]]::new()
    $segments.Add($first.FullName)
    for ($number = 2; $number -le 99; $number++) {
        $candidate = "$base.ad$number"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $segments.Add((Resolve-Path -LiteralPath $candidate).Path)
        }
        else {
            $later = Get-ChildItem -LiteralPath $first.DirectoryName -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match ('^' + [regex]::Escape([System.IO.Path]::GetFileNameWithoutExtension($first.Name)) + '\.ad(\d+)$') -and [int]$Matches[1] -gt $number } |
                Select-Object -First 1
            if ($later) { throw "Обнаружен пропуск сегмента: отсутствует $candidate, но найден $($later.Name)." }
            break
        }
    }
    $resolvedImages = @($segments)
}

$scriptPath = Join-Path $PSScriptRoot '..\Инструменты\AD1\Разобрать_AD1.py'
$wheelhouse = Join-Path $PSScriptRoot '..\Инструменты\AD1\wheelhouse'
if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { throw "Не найден Python-сценарий: $scriptPath" }
if (-not (Test-Path -LiteralPath $wheelhouse -PathType Container)) { throw "Не найдена офлайн-папка зависимостей: $wheelhouse" }

if ($PythonPath) {
    $basePython = (Resolve-Path -LiteralPath $PythonPath).Path
}
else {
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if (-not $pyLauncher) { throw 'Нужен Python 3.10 или новее. Укажи его полный путь параметром -PythonPath; интернет для установки пакетов не требуется.' }
    $basePython = $pyLauncher.Source
}

if ($PythonPath) {
    $versionText = & $basePython -c 'import sys; print("%d.%d" % sys.version_info[:2])'
    $architecture = & $basePython -c 'import struct; print(struct.calcsize("P") * 8)'
}
else {
    $versionText = & $basePython -3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'
    $architecture = & $basePython -3 -c 'import struct; print(struct.calcsize("P") * 8)'
}
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch '^\d+\.\d+$') { throw 'Не удалось запустить Python. Проверь -PythonPath.' }
$version = [version]($versionText + '.0')
if ($version -lt [version]'3.10.0') { throw "Python $versionText слишком старый; нужен Python 3.10 или новее." }
if ($architecture -ne '64') { throw 'Нужен 64-битный Python: локальный пакет dissect.util в комплекте собран для Windows x64.' }

$tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
$envPath = Join-Path $tempRoot "Cybersec_AD1_Python_$($version.Major).$($version.Minor)_evidence313"
$venvPython = Join-Path $envPath 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    if ($PythonPath) { & $basePython -m venv $envPath }
    else { & $basePython -3 -m venv $envPath }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) { throw 'Не удалось создать локальное Python-окружение в TEMP.' }
}

$null = & $venvPython -c 'import dissect.evidence' 2>$null
if ($LASTEXITCODE -ne 0) {
    & $venvPython -m pip install --disable-pip-version-check --no-index --find-links $wheelhouse 'dissect.evidence==3.13'
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось установить парсер из локальных wheel-файлов. Интернет здесь не используется.' }
}

$arguments = @($scriptPath, '--images') + $resolvedImages + @('--output', [System.IO.Path]::GetFullPath($OutputDirectory))
if ($ListOnly) { $arguments += '--list-only' }
& $venvPython @arguments
exit $LASTEXITCODE
