[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)][string[]]$EvidencePath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [ValidateSet('Auto','RAM','Disk','AD1','Logical')][string]$Type='Auto',
    [string]$CaseName,
    [switch]$SkipHash,
    [switch]$MetadataOnly,
    [switch]$SkipMemoryStrings,
    [switch]$AllowSymbolDownload,
    [string]$PythonExe
)

$ErrorActionPreference='Stop'

function Quote-Argument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1') + '"'
}

function Resolve-EvidenceType([string]$Path,[string]$Requested) {
    if ($Requested -ne 'Auto') { return $Requested }
    $item=Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) { return 'Logical' }
    $ext=$item.Extension.ToLowerInvariant()
    if ($ext -eq '.raw') { throw "Расширение .raw неоднозначно (RAM или диск): укажи явно -Type RAM либо -Type Disk для '$Path'." }
    if ($ext -match '^\.ad\d+$') { return 'AD1' }
    if ($ext -in @('.mem','.dmp','.raw','.vmem','.lime','.core','.dump')) { return 'RAM' }
    if ($ext -in @('.e01','.ex01','.aff4','.vmdk','.vhd','.vhdx','.vdi','.001','.img','.dd','.iso','.qcow2','.vma')) { return 'Disk' }
    throw "Не удалось определить тип '$Path'. Укажи -Type RAM, Disk, AD1 или Logical. Для диска с необычным расширением используй -Type Disk."
}

function Normalize-FirstSegment([string]$Path,[string]$Kind) {
    $item=Get-Item -LiteralPath $Path
    if($item.PSIsContainer){return $item.FullName}
    $name=[IO.Path]::GetFileNameWithoutExtension($item.Name)
    $ext=$item.Extension
    $first=$null
    if($Kind -eq 'AD1' -and $ext -match '^\.ad\d+$') { $first=Join-Path $item.DirectoryName ($name+'.ad1') }
    elseif($Kind -eq 'Disk' -and $ext -match '^\.e\d\d$') { $first=Join-Path $item.DirectoryName ($name+'.E01') }
    elseif($Kind -eq 'Disk' -and $ext -match '^\.\d{3}$') { $first=Join-Path $item.DirectoryName ($name+'.001') }
    if($first -and (Test-Path -LiteralPath $first -PathType Leaf)){return (Resolve-Path -LiteralPath $first).Path}
    return $item.FullName
}

function Invoke-ChildPowerShell([string]$Script,[string[]]$ScriptArguments,[string]$Stdout,[string]$Stderr) {
    $shell=Get-Command pwsh.exe,powershell.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $shell) { throw 'Не найден PowerShell для запуска сценариев.' }
    $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Script)+$ScriptArguments
    $psi=[Diagnostics.ProcessStartInfo]::new()
    $psi.FileName=$shell.Source
    $psi.Arguments=(($args | ForEach-Object { Quote-Argument ([string]$_) }) -join ' ')
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.StandardOutputEncoding=[Text.Encoding]::UTF8
    $psi.StandardErrorEncoding=[Text.Encoding]::UTF8
    $proc=[Diagnostics.Process]::new(); $proc.StartInfo=$psi
    if (-not $proc.Start()) { throw "Не удалось запустить $Script" }
    $outTask=$proc.StandardOutput.ReadToEndAsync(); $errTask=$proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    [IO.File]::WriteAllText($Stdout,$outTask.Result,[Text.UTF8Encoding]::new($true))
    [IO.File]::WriteAllText($Stderr,$errTask.Result,[Text.UTF8Encoding]::new($true))
    return $proc.ExitCode
}

$resolvedRaw=@(foreach($path in $EvidencePath) { (Resolve-Path -LiteralPath $path).Path })
if (-not $resolvedRaw.Count) { throw 'Укажи хотя бы один файл или папку с уликой.' }
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$resolved=@(foreach($path in $resolvedRaw){$kind=Resolve-EvidenceType $path $Type;$first=Normalize-FirstSegment $path $kind;if($seen.Add($first)){$first}})
$root=[IO.Path]::GetFullPath($OutputRoot)
foreach($path in $resolved) {
    $item=Get-Item -LiteralPath $path
    $parent=if($item.PSIsContainer){$item.FullName.TrimEnd('\')}else{$item.DirectoryName.TrimEnd('\')}
    if($root.TrimEnd('\').Equals($parent,[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase)) {
        throw "Папка результатов '$root' расположена внутри исходных данных '$parent'. Выбери отдельное место для результатов."
    }
}
New-Item -ItemType Directory -Path $root -Force | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$safeCase=if($CaseName){$CaseName}else{'DFIR_'+$stamp}
$safeCase=$safeCase -replace '[<>:"/\\|?*]','_' -replace '\s+','_'
$run=Join-Path $root ($safeCase+'_'+$stamp)
New-Item -ItemType Directory -Path $run -Force | Out-Null
$scripts=$PSScriptRoot
$ramScript=Join-Path $scripts 'Собрать_первичный_отчёт_по_RAM.ps1'
$diskScript=Join-Path $scripts 'Собрать_первичный_отчёт_по_образу.ps1'
$ad1Script=Join-Path $scripts 'Собрать_отчёт_по_AD1.ps1'
$rows=[Collections.Generic.List[object]]::new()
$manifest=[Collections.Generic.List[object]]::new()
$n=0
foreach($path in $resolved) {
    $n++
    $kind=Resolve-EvidenceType $path $Type
    $path=Normalize-FirstSegment $path $kind
    $item=Get-Item -LiteralPath $path
    $label=('{0:D2}_{1}' -f $n,($item.BaseName -replace '[<>:"/\\|?*]','_'))
    $dest=Join-Path $run $label
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Write-Host "[$n/$($resolved.Count)] $kind : $path"
    $hash='НЕ вычислялся'
    if(-not $item.PSIsContainer -and -not $SkipHash) {
        try { $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
        catch { $hash='ОШИБКА: '+$_.Exception.Message }
    }
    $manifest.Add([pscustomobject]@{Путь=$path;Тип=$kind;Размер=if($item.PSIsContainer){$null}else{$item.Length};Изменён=$item.LastWriteTimeUtc.ToString('o');SHA256=$hash})
    $stdout=Join-Path $dest 'Вывод_скрипта.txt'; $stderr=Join-Path $dest 'Ошибки_скрипта.txt'
    $childCode=9009; $report=''; $note=''
    try {
        switch($kind) {
            'RAM' {
                $argv=@('-MemoryPath',$path,'-OutputRoot',$dest)
                if($PythonExe){$argv+=@('-PythonExe',$PythonExe)}
                if(-not $SkipMemoryStrings){$argv+= '-ScanMemoryStrings'}
                if($AllowSymbolDownload){$argv+= '-AllowSymbolDownload'}
                $childCode=Invoke-ChildPowerShell $ramScript $argv $stdout $stderr
                $candidate=Join-Path $dest 'RAM_*'
                $report=Get-ChildItem -Path $candidate -Filter 'Первичный_отчёт_RAM.md' -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                if(-not $report){$note='Отчёт RAM не создан. Проверь журнал ошибок, наличие Python и локального набора Volatility.'}
            }
            'Disk' {
                $argv=@('-ImagePath',$path,'-OutputDirectory',$dest,'-CaseName',$item.BaseName)
                if($SkipHash){$argv+= '-SkipHash'}
                if($MetadataOnly){$argv+= '-MetadataOnly'}
                $childCode=Invoke-ChildPowerShell $diskScript $argv $stdout $stderr
                $report=Get-ChildItem -LiteralPath $dest -Recurse -Filter 'Первичный_отчёт_по_образу.md' -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                if(-not $report){$note='Отчёт по образу не создан. Проверь журнал и наличие Sleuth Kit в комплекте.'}
            }
            'AD1' {
                $argv=@('-ImagePath',$path,'-OutputDirectory',$dest)
                if($PythonExe){$argv+=@('-PythonPath',$PythonExe)}
                $childCode=Invoke-ChildPowerShell $ad1Script $argv $stdout $stderr
                $report=Get-ChildItem -LiteralPath $dest -Recurse -Include '*.md','*.html' -File -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'AD1|AD'} | Select-Object -First 1 -ExpandProperty FullName
                if($childCode -ne 0){$note='Парсер AD1 сообщил неполный разбор или ошибки. Сверь список ошибок и контрольные суммы файлов; ненулевой код не означает, что весь контейнер прочитан.'}
            }
            'Logical' {
                if(-not $item.PSIsContainer){throw 'Для типа Logical укажи папку с уже экспортированными файлами.'}
                $argv=@('-ImagePath',$path,'-OutputDirectory',$dest,'-CaseName',$item.Name,'-ImageType','logical')
                if($SkipHash){$argv+= '-SkipHash'}
                if($MetadataOnly){$argv+= '-MetadataOnly'}
                $childCode=Invoke-ChildPowerShell $diskScript $argv $stdout $stderr
                $report=Get-ChildItem -LiteralPath $dest -Recurse -Filter 'Первичный_отчёт_по_образу.md' -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                $note='Логический экспорт: нет исходных секторов, удалённых записей или полного контекста файловой системы.'
            }
        }
    } catch { $note=$_.Exception.Message; [IO.File]::AppendAllText($stderr,$note+[Environment]::NewLine,[Text.Encoding]::UTF8) }
    $rows.Add([pscustomobject]@{Номер=$n;Тип=$kind;Источник=$path;Код=$childCode;Отчёт=$report;Папка=$dest;Примечание=$note})
    if($childCode -eq 0){Write-Host "  Готово, отчет: $report"}else{Write-Warning "  Сценарий завершился с кодом $childCode. Остальные улики будут обработаны; см. $dest"}
}

$manifest | Export-Csv -LiteralPath (Join-Path $run 'Реестр_исходных_данных.csv') -NoTypeInformation -Encoding UTF8
$rows | Export-Csv -LiteralPath (Join-Path $run 'Статус_обработки.csv') -NoTypeInformation -Encoding UTF8
$lines=[Collections.Generic.List[string]]::new()
$lines.Add('# Сводка автоматизированного DFIR-разбора');$lines.Add('');$lines.Add("- Дело: $safeCase");$lines.Add("- Запуск: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')");$lines.Add("- Обработано источников: $($rows.Count)");$lines.Add('- Исходные данные не изменялись намеренно; результаты записаны отдельно.');$lines.Add('- Автоматические совпадения — направления проверки, а не доказательство компрометации.');$lines.Add('- Если строка не обнаружена, это не доказывает её отсутствия: учитывай формат, символы, пропуски чтения и ограничения плагинов.');$lines.Add('');$lines.Add('## Источники и результаты');$lines.Add('')
foreach($row in $rows){$lines.Add("### $($row.Номер). $($row.Тип): $($row.Источник)");$lines.Add('');$lines.Add("- Код дочернего сценария: $($row.Код)");if($row.Отчёт){$rel=$row.Отчёт.Substring($run.Length).TrimStart('\','/');$lines.Add("- Отчёт: [$rel]($($rel -replace '\\','/'))")}else{$lines.Add('- Отчёт: не создан')};$folder=Split-Path $row.Папка -Leaf;$lines.Add("- Журнал вывода: [$folder/Вывод_скрипта.txt]");$lines.Add("- Журнал ошибок: [$folder/Ошибки_скрипта.txt]");if($row.Примечание){$lines.Add("- Примечание: $($row.Примечание)")};$lines.Add('')}
$lines.Add('## Что делать дальше');$lines.Add('');$lines.Add('1. Сверь SHA256 и размер источников с переданными организаторами значениями.');$lines.Add('2. Открой каждый подробный отчет и соответствующие исходные выводы инструментов.');$lines.Add('3. Подтверди подозрительные процессы, файлы, подключения и временные метки соседними артефактами.');$lines.Add('4. Для AD1 с ошибками добейся повторного разбора поддерживаемым просмотрщиком и зафиксируй неполноту.');$lines.Add('5. Не запускай найденные исполняемые файлы; извлекай их только в отдельную лабораторную папку.');$lines.Add('')
$lines | Set-Content -LiteralPath (Join-Path $run 'Сводный_отчёт.md') -Encoding UTF8
Write-Host "`nСводный отчет: $(Join-Path $run 'Сводный_отчёт.md')"
Write-Host "Материалы дела: $run"
