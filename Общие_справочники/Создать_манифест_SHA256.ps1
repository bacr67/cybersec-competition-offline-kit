[CmdletBinding()]
param(
    [string]$Root = (Join-Path $PSScriptRoot '..'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Контрольные_суммы_SHA256.txt')
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$manifestPath = [IO.Path]::GetFullPath($OutputPath)
if (-not $manifestPath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Файл манифеста должен находиться внутри корня комплекта.'
}

$manifestRelative = $manifestPath.Substring($rootPath.Length + 1).Replace('\','/')
$files = @(Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force |
    Where-Object {
        $_.FullName -ne $manifestPath -and
        $_.FullName.Substring($rootPath.Length + 1) -notmatch '(^|[\\/])\.git([\\/]|$)'
    } |
    Sort-Object { $_.FullName.Substring($rootPath.Length + 1).Replace('\','/') })

$tempPath = $manifestPath + '.tmp'
$encoding = [Text.UTF8Encoding]::new($false)
$writer = [IO.StreamWriter]::new($tempPath, $false, $encoding)
try {
    $index = 0
    foreach ($file in $files) {
        $index++
        $relative = $file.FullName.Substring($rootPath.Length + 1).Replace('\','/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $writer.WriteLine("$hash  $relative")
        if ($index % 500 -eq 0) { Write-Progress -Activity 'Считаю SHA-256 комплекта' -Status "$index из $($files.Count) файлов" -PercentComplete (100 * $index / [Math]::Max(1,$files.Count)) }
    }
}
finally {
    $writer.Dispose()
    Write-Progress -Activity 'Считаю SHA-256 комплекта' -Completed
}

Move-Item -LiteralPath $tempPath -Destination $manifestPath -Force
Write-Host "Манифест обновлён: $manifestPath"
Write-Host "Файлов включено: $($files.Count)"
Write-Host 'Для проверки копии сравните хэши файлов с этим списком.'
