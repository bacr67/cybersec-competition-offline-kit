[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [string]$StringsExe = (Join-Path $PSScriptRoot '..\Инструменты\Sysinternals\strings.exe')
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $Path).Path
$sourceItem = Get-Item -LiteralPath $source
$sourceRoot = if ($sourceItem.PSIsContainer) { $source } else { $sourceItem.DirectoryName }
$out = [System.IO.Path]::GetFullPath($OutDir)
if ($out.Equals($sourceRoot,[StringComparison]::OrdinalIgnoreCase) -or $out.StartsWith($sourceRoot.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Папка результатов должна находиться вне папки исходных данных.'
}
if (!(Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
$out = (Resolve-Path -LiteralPath $out).Path
$files = if ($sourceItem.PSIsContainer) { Get-ChildItem -LiteralPath $source -File -Recurse -Force } else { $sourceItem }
$rows = foreach ($file in $files) {
    $hash = ''; $hashError = ''
    try { $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { $hashError = $_.Exception.Message }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    $stream = [IO.File]::OpenRead($file.FullName)
    try { $buffer = New-Object byte[] 8; $read = $stream.Read($buffer,0,$buffer.Length) }
    finally { $stream.Dispose() }
    $hex = if ($read -gt 0) { [BitConverter]::ToString($buffer,0,$read) } else { '' }
    $magic = if ($read -ge 2 -and $buffer[0] -eq 0x4D -and $buffer[1] -eq 0x5A) {'MZ / возможный Windows PE'} elseif ($read -ge 4 -and $hex.StartsWith('7B-5C-72-74')) {'RTF'} elseif ($hex.StartsWith('25-50-44-46')) {'PDF'} elseif ($hex.StartsWith('50-4B-03-04')) {'Контейнер ZIP'} elseif ($hex.StartsWith('1F-8B')) {'GZIP'} elseif ($hex.StartsWith('7F-45-4C-46')) {'ELF'} else {'Неизвестный/другой формат'}
    $base = [IO.Path]::GetFileNameWithoutExtension($file.Name) -replace '[^A-Za-z0-9._-]','_'
    $hashSuffix = if ($hash.Length -ge 12) { $hash.Substring(0,12) } else { 'nohash' }
    $stringFile = Join-Path $out ($base + '_' + $hashSuffix + '_strings.txt')
    $stringStatus = 'strings.exe не найден; только метаданные'
    if (Test-Path -LiteralPath $StringsExe) {
        try { & $StringsExe -n 6 $file.FullName 2>&1 | Set-Content -LiteralPath $stringFile -Encoding UTF8; $stringStatus = $stringFile }
        catch { $stringStatus = 'ошибка strings.exe: ' + $_.Exception.Message }
    }
    [pscustomobject]@{
        SourcePath = $file.FullName
        Bytes = $file.Length
        ModifiedUtc = $file.LastWriteTimeUtc.ToString('o')
        SHA256 = $hash
        HashError = $hashError
        FirstBytesHex = $hex
        DetectedMagic = $magic
        SignatureStatus = if ($signature) {[string]$signature.Status} else {''}
        Signer = if ($signature -and $signature.SignerCertificate) {$signature.SignerCertificate.Subject} else {''}
        StringsOutput = $stringStatus
        Warning = 'Только статические метаданные. Скрипт не запускает образец.'
    }
}
$csvPath = Join-Path $out 'Статические_метаданные.csv'
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
$summary = @(
    '# Сводка статического триажа','',
    "- Проверено файлов: $(@($rows).Count)",
    "- SHA-256 ошибок: $(@($rows | Where-Object HashError).Count)",
    "- Файлы с сигнатурой Authenticode Valid: $(@($rows | Where-Object SignatureStatus -eq 'Valid').Count)",
    "- Файлы без Valid-подписи: $(@($rows | Where-Object { $_.SignatureStatus -and $_.SignatureStatus -ne 'Valid' }).Count)",
    '- Вывод strings и эвристика magic — только подсказки; исполняемые файлы не запускались.',
    '- Проверь хэш, цифровую подпись, путь, метки времени и контекст в отдельной песочнице.'
)
$summary | Set-Content -LiteralPath (Join-Path $out 'Сводка_статического_триажа.md') -Encoding UTF8
Write-Host "Статические метаданные: $csvPath; файлы не запускались."

