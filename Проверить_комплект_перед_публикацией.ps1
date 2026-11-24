[CmdletBinding()]
param(
    [string]$Root = $PSScriptRoot,
    [string]$OutputDirectory = (Join-Path $env:TEMP 'Аудит_публикации_комплекта'),
    [switch]$IncludeTools
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.TrimEnd('\').Equals($rootPath.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) -or
    $output.StartsWith($rootPath.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Результаты аудита укажи вне проверяемого комплекта, чтобы не смешивать их с публикацией.'
}
if (-not (Test-Path -LiteralPath $output)) { New-Item -ItemType Directory -Path $output -Force | Out-Null }
$output = (Resolve-Path -LiteralPath $output).Path

$files = @(Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
    $relative = $_.FullName.Substring($rootPath.Length).TrimStart('\')
    if (-not $IncludeTools -and $relative -match '(^|\\)(Инструменты|render[^\\]*|проверка_страниц|registry_manual_QA)(\\|$)') { return $false }
    $_.Extension -in @('.md','.txt','.ps1','.psm1','.py','.yaml','.yml','.json','.xml','.ini','.conf','.csv','.html','.js','.toml') -or $_.Name -in @('.env','id_rsa','id_ed25519')
})

$secretRules = @(
    [pscustomobject]@{ Name='Закрытый ключ PEM'; Regex='-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----' },
    [pscustomobject]@{ Name='AWS access key id'; Regex='\bAKIA[0-9A-Z]{16}\b' },
    [pscustomobject]@{ Name='GitHub token'; Regex='\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b' },
    [pscustomobject]@{ Name='OpenAI-style API key'; Regex='\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b' },
    [pscustomobject]@{ Name='Credential assignment'; Regex='(?i)\b(?:password|passwd|client_secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*["'']?[A-Za-z0-9/+_=-]{20,}' }
)
$findings = [System.Collections.Generic.List[object]]::new()
foreach ($file in $files) {
    try {
        $lineNumber = 0
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            $lineNumber++
            foreach ($rule in $secretRules) {
                if ($line -match $rule.Regex) {
                    $findings.Add([pscustomobject]@{ RelativePath=$file.FullName.Substring($rootPath.Length+1); Line=$lineNumber; Rule=$rule.Name; Value='НЕ СОХРАНЯЕТСЯ' })
                    break
                }
            }
        }
    }
    catch { $findings.Add([pscustomobject]@{ RelativePath=$file.FullName.Substring($rootPath.Length+1); Line=''; Rule='Не удалось прочитать файл'; Value='Проверьте вручную' }) }
}
$findings | Export-Csv -LiteralPath (Join-Path $output 'Совпадения_секретов.csv') -NoTypeInformation -Encoding UTF8

$largeFiles = @(Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object Length -ge 50MB | ForEach-Object {
    [pscustomobject]@{ RelativePath=$_.FullName.Substring($rootPath.Length+1); SizeBytes=$_.Length; SizeMB=[math]::Round($_.Length/1MB,1) }
})
$largeFiles | Export-Csv -LiteralPath (Join-Path $output 'Крупные_файлы.csv') -NoTypeInformation -Encoding UTF8

$secretText = if ($findings.Count -eq 0) { 'Совпадений с заданными высокоточными шаблонами в текстовых файлах не найдено. Это не заменяет ручную проверку.' } else { "Найдено совпадений: $($findings.Count). Открой Совпадения_секретов.csv; значения секрета не записываются." }
$report = @(
    '# Проверка комплекта перед публикацией','',
    "- Папка: ``$rootPath``",
    "- Проверено текстовых файлов: $($files.Count)",
    "- $secretText",
    "- Файлов размером от 50 МБ: $($largeFiles.Count); см. Крупные_файлы.csv.",
    '- По умолчанию каталог `Инструменты` исключён из поиска секретов, чтобы не разбирать тысячи файлов поставщиков. Проверьте список крупных инструментов отдельно.',
    '- Перед публичной публикацией отдельно проверьте лицензии, права на дистрибуцию, персональные данные и соответствие правилам соревнования.',
    '- Сканер ищет только ограниченный набор шаблонов и может давать ложные совпадения/пропуски. Он не сертифицирует пакет как безопасный.'
)
$report | Set-Content -LiteralPath (Join-Path $output 'Отчёт_аудита_публикации.md') -Encoding UTF8
Write-Host "Аудит готов: $(Join-Path $output 'Отчёт_аудита_публикации.md')"
Write-Host "Текстовых файлов: $($files.Count); совпадений секретов: $($findings.Count); крупных файлов: $($largeFiles.Count)"
