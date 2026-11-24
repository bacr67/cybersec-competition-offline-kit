param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [switch]$SkipHash
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $Path).Path
$sourceItem = Get-Item -LiteralPath $source
$out = [System.IO.Path]::GetFullPath($OutDir)
$sourceDirectory = if ($sourceItem.PSIsContainer) { $source.TrimEnd('\') } else { $sourceItem.DirectoryName.TrimEnd('\') }
if ($out.TrimEnd('\').Equals($sourceDirectory, [System.StringComparison]::OrdinalIgnoreCase) -or
    $out.StartsWith($sourceDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutDir должен находиться вне исходного файла/папки.'
}
if (-not (Test-Path -LiteralPath $out)) {
    New-Item -ItemType Directory -Path $out -Force | Out-Null
}
$out = (Resolve-Path -LiteralPath $out).Path

if ($sourceItem.PSIsContainer) {
    $sourceRoot = $source.TrimEnd('\') + '\'
    if ($out.TrimEnd('\\').Equals($source.TrimEnd('\\'), [System.StringComparison]::OrdinalIgnoreCase) -or
        $out.StartsWith($sourceRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutDir должен находиться вне папки с исходными evidence.'
    }
    $files = Get-ChildItem -LiteralPath $source -File -Recurse
} else {
    $files = @($sourceItem)
}

$rows = foreach ($file in $files) {
    $hash = ''
    if (-not $SkipHash) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    [pscustomobject]@{
        Name = $file.Name
        FullPath = $file.FullName
        Extension = $file.Extension
        LengthBytes = $file.Length
        CreationTimeUtc = $file.CreationTimeUtc.ToString('o')
        LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
        SHA256 = $hash
    }
}

$csvPath = Join-Path $out 'Манифест_образа.csv'
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Манифест: $csvPath"
if ($SkipHash) { Write-Host 'SHA-256 пропущен по параметру -SkipHash.' }
else { Write-Host 'SHA-256 посчитан для каждого файла; для большого образа это может занять время.' }
