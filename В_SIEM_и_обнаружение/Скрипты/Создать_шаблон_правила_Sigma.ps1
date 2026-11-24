[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Title,
    [Parameter(Mandatory=$true)][ValidateSet('process_creation','network_connection','file_event','registry_event','dns_query')][string]$Category,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Field,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Value,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('contains','startswith','endswith','re','equals')][string]$Modifier='contains',
    [ValidateSet('low','medium','high','critical')][string]$Level='medium',
    [string]$Product='windows',
    [string]$Description='Новое тестовое правило. Добавьте контекст источника и проверенные поля.',
    [string[]]$Tags=@('attack.execution')
)

$ErrorActionPreference = 'Stop'
function ConvertTo-YamlSingleQuoted {
    param([Parameter(Mandatory=$true)][string]$Text)
    return "'" + ($Text -replace "'", "''" -replace "`r|`n", ' ') + "'"
}
if ([string]::IsNullOrWhiteSpace($Field) -or $Field -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Field должен содержать только латинские буквы, цифры, точку, подчёркивание или дефис.' }
if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\r\n]') { throw 'Value должен быть одним значением без переноса строки.' }
if ($Modifier -eq 'equals') { $selectionKey=$Field } else { $selectionKey="$Field|$Modifier" }
if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$out = (Resolve-Path -LiteralPath $OutputDirectory).Path
$slug = ($Title.ToLowerInvariant() -replace '[^a-z0-9]+','_' -replace '^_|_$','')
if (-not $slug) { $slug='sigma_rule' }
$ruleId = [guid]::NewGuid()
$rulePath = Join-Path $out ($slug + '_' + $ruleId.ToString('N').Substring(0,8) + '.yml')
$tagLines = foreach($tag in $Tags){ "  - $(ConvertTo-YamlSingleQuoted $tag)" }
$yaml = @(
    "title: $(ConvertTo-YamlSingleQuoted $Title)",
    "id: $ruleId",
    'status: test',
    "description: $(ConvertTo-YamlSingleQuoted $Description)",
    "author: $(ConvertTo-YamlSingleQuoted 'Участник')",
    "date: $([DateTime]::UtcNow.ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture))",
    'logsource:',
    "  category: $Category",
    "  product: $Product",
    'detection:',
    '  selection:',
    "    ${selectionKey}: $(ConvertTo-YamlSingleQuoted $Value)",
    '  condition: selection',
    'falsepositives:',
    "  - $(ConvertTo-YamlSingleQuoted 'Легитимное администрирование или тестовая активность с тем же признаком')",
    "level: $Level",
    'tags:'
) + @($tagLines)
$yaml | Set-Content -LiteralPath $rulePath -Encoding UTF8

$testPath = Join-Path $out ($slug + '_Проверка.md')
$test = @(
    "# Проверка правила: $Title",'',
    "- Sigma YAML: ``$([IO.Path]::GetFileName($rulePath))``",
    "- Поле/условие: ``$selectionKey``",
    "- Тестовое значение: ``$Value``",
    '- Источник событий / index / sourcetype: заполнить по стенду.',
    '- Имена реальных полей проверить на исходном событии; Sigma не запускается напрямую в SIEM.','',
    '## Положительная проверка','',
    '1. Найдите безопасное тестовое событие, в котором поле совпадает с тестовым значением.',
    '2. Убедитесь, что правило срабатывает и указывает ожидаемые host/user/process/time.','',
    '## Отрицательная проверка','',
    '1. Возьмите легитимное похожее событие, где поле не совпадает.',
    '2. Убедитесь, что правило не срабатывает либо документируйте ожидаемый FP.','',
    '## Перед включением','',
    'Проверьте синтаксис Sigma, backend-конвертацию, доступность телеметрии, дедупликацию, временную зону, FP/FN и ATT&CK-тег. Сначала держите status=test; не включайте production-оповещение без проверки.'
)
$test | Set-Content -LiteralPath $testPath -Encoding UTF8
Write-Host "Создано тестовое Sigma-правило: $rulePath"
Write-Host "План положительной/отрицательной проверки: $testPath"
Write-Host 'Проверьте YAML и соответствие полей формату своей SIEM: генератор не выполняет Sigma backend-конвертацию.'
