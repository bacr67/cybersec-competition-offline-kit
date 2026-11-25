[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ImagePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$CaseName,

    [ValidateSet('Auto', 'raw', 'ewf', 'vmdk', 'vhd', 'logical')]
    [string]$ImageType = 'Auto',

    [ValidateSet(512, 1024, 2048, 4096)]
    [int]$SectorSize = 512,

    [ValidateRange(0, [long]::MaxValue)]
    [long]$Offset = -1,

    [string]$TimeZone,

    [ValidateRange(1, 500)]
    [int]$MaxFindings = 100,

    [switch]$SkipHash,

    [switch]$MetadataOnly
)

$ErrorActionPreference = 'Stop'

function Invoke-ReadOnlyTool {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$OutputFile
    )

    try {
        & $Executable @Arguments 2>&1 | Out-File -LiteralPath $OutputFile -Encoding utf8
        return $LASTEXITCODE
    }
    catch {
        $_ | Out-String | Set-Content -LiteralPath $OutputFile -Encoding utf8
        return 9009
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Priority,
        [string]$Confidence,
        [string]$Evidence,
        [string]$Description,
        [string]$NextStep
    )
    $script:findings.Add([pscustomobject]@{
        Категория = $Category
        Приоритет = $Priority
        Уверенность = $Confidence
        Доказательство = $Evidence
        Описание = $Description
        СледующийШаг = $NextStep
    })
}

function ConvertTo-SafeMarkdown {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace '\|', '\|' -replace "`r?`n", ' ')
}

$resolvedInputs = @($ImagePath | ForEach-Object { (Resolve-Path -LiteralPath $_).Path })
if ($resolvedInputs.Count -eq 0) { throw 'Укажи хотя бы один образ или сегмент.' }
$resolvedImage = $resolvedInputs[0]
$imageItem = Get-Item -LiteralPath $resolvedImage
$isLogicalDirectory = [bool]$imageItem.PSIsContainer
if ($isLogicalDirectory -and ($resolvedInputs.Count -ne 1 -or $ImageType -notin @('Auto', 'logical'))) {
    throw 'Для логического источника укажи одну папку и -ImageType logical.'
}
if ($isLogicalDirectory) { $ImageType = 'logical' }

$findings = [System.Collections.Generic.List[object]]::new()
$imageFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
if (-not $isLogicalDirectory) { $imageFiles.Add($imageItem) }

if ($resolvedInputs.Count -gt 1) {
    $imageFiles.Clear()
    foreach ($input in $resolvedInputs) {
        $item = Get-Item -LiteralPath $input
        if ($item.PSIsContainer) { throw 'Явный список сегментов должен содержать только файлы.' }
        $imageFiles.Add($item)
    }
}

# Если выбран первый сегмент EWF или RAW, автоматически добавляем следующие части.
$segmentPattern = [regex]::Match($imageItem.FullName, '^(.*)\.E01$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$segmentKind = 'EWF'
if (-not $isLogicalDirectory -and -not $segmentPattern.Success -and $resolvedInputs.Count -eq 1) {
    $segmentPattern = [regex]::Match($imageItem.FullName, '^(.*)\.001$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $segmentKind = 'RAW'
}
if (-not $isLogicalDirectory -and $segmentPattern.Success -and $resolvedInputs.Count -eq 1) {
    $basePath = $segmentPattern.Groups[1].Value
    for ($part = 2; $part -le 99; $part++) {
        $number = '{0:D2}' -f $part
        $candidate = if ($segmentKind -eq 'EWF') { "$basePath.E$number" } else { "$basePath.{0:D3}" -f $part }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $imageFiles.Add((Get-Item -LiteralPath $candidate))
        }
        elseif (Test-Path -LiteralPath $(if ($segmentKind -eq 'EWF') { "$basePath.E{0:D2}" -f ($part + 1) } else { "$basePath.{0:D3}" -f ($part + 1) }) -PathType Leaf) {
            Add-Finding -Category 'Целостность набора образа' -Priority 'Высокий' -Confidence 'Средний' `
                -Evidence "После сегмента $($imageFiles[$imageFiles.Count - 1].Name) обнаружен пропуск номера части." `
                -Description 'В наборе сегментов, вероятно, не хватает одного или нескольких файлов.' `
                -NextStep 'Сверь список файлов с перечнем организатора и не продолжай анализ неполного набора.'
            break
        }
        else {
            break
        }
    }
}

$fullOutputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
 $sourceDirectories = if ($isLogicalDirectory) { @($imageItem.FullName) } else { @($imageFiles | ForEach-Object { $_.DirectoryName } | Select-Object -Unique) }
foreach ($sourceDirectory in $sourceDirectories) {
    $evidenceDirectory = $sourceDirectory.TrimEnd('\') + '\'
    if ($fullOutputRoot.TrimEnd('\').Equals($sourceDirectory.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullOutputRoot.StartsWith($evidenceDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Папка результатов должна быть вне папок с исходными доказательствами.'
    }
}
if ([string]::IsNullOrWhiteSpace($CaseName)) { $CaseName = $imageItem.BaseName }
$safeCaseName = $CaseName -replace '[<>:"/\\|?*]', '_'
if (-not (Test-Path -LiteralPath $fullOutputRoot)) {
    New-Item -ItemType Directory -Path $fullOutputRoot -Force | Out-Null
}
$fullOutputRoot = (Resolve-Path -LiteralPath $fullOutputRoot).Path
$runFolderName = 'Разбор_{0}_{1}' -f $safeCaseName, [DateTime]::Now.ToString('yyyyMMdd_HHmmss')
$fullOutputPath = Join-Path $fullOutputRoot $runFolderName
New-Item -ItemType Directory -Path $fullOutputPath -Force | Out-Null
$toolRoot = Join-Path $PSScriptRoot '..\Инструменты\Образы_дисков\SleuthKit\sleuthkit-4.14.0-win32\bin'
$imageInfoExe = Join-Path $toolRoot 'tsk_imageinfo.exe'
$mmlsExe = Join-Path $toolRoot 'mmls.exe'
$fsstatExe = Join-Path $toolRoot 'fsstat.exe'
$flsExe = Join-Path $toolRoot 'fls.exe'

foreach ($required in @($imageInfoExe, $mmlsExe, $fsstatExe, $flsExe)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Не найден инструмент комплекта: $required. Проверь, что папка Инструменты скопирована полностью."
    }
}

$imageArguments = if ($isLogicalDirectory) { @($imageItem.FullName) } else { @($imageFiles | ForEach-Object { $_.FullName }) }
$commonImageOptions = @()
if ($ImageType -ne 'Auto') { $commonImageOptions += @('-i', $ImageType) }
if (-not $isLogicalDirectory) { $commonImageOptions += @('-b', [string]$SectorSize) }
function Add-ImageOptions {
    param([string[]]$Arguments)
    return ,($commonImageOptions + $Arguments)
}
$imageRecords = foreach ($file in $imageFiles) {
    $hash = ''
    if (-not $SkipHash) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    [pscustomobject]@{
        ИмяФайла = $file.Name
        ПолныйПуть = $file.FullName
        РазмерБайт = $file.Length
        SHA256 = $hash
        ИзменёнUTC = $file.LastWriteTimeUtc.ToString('o')
    }
}
if ($isLogicalDirectory) {
    $imageRecords = @([pscustomobject]@{
        ИмяФайла = $imageItem.Name; ПолныйПуть = $imageItem.FullName
        РазмерБайт = 0; SHA256 = ''; ИзменёнUTC = $imageItem.LastWriteTimeUtc.ToString('o')
    })
}
$imageRecords | Export-Csv -LiteralPath (Join-Path $fullOutputPath 'Состав_образа.csv') -NoTypeInformation -Encoding UTF8
$sidecarHashNote = 'Сопроводительный файл с контрольными суммами не найден.'
if (-not $isLogicalDirectory -and $resolvedInputs.Count -eq 1 -and -not $imageItem.PSIsContainer) {
    $sidecarPath = $imageItem.FullName + '.txt'
    if (Test-Path -LiteralPath $sidecarPath -PathType Leaf) {
        $sidecarText = Get-Content -LiteralPath $sidecarPath -Raw -Encoding UTF8
        $hashResults = [System.Collections.Generic.List[string]]::new()
        foreach ($algorithm in @('MD5','SHA1')) {
            $expectedLength = if ($algorithm -eq 'MD5') { 32 } else { 40 }
            $expectedMatch = [regex]::Match($sidecarText, "(?im)^\s*$algorithm checksum:\s*([0-9a-f]{$expectedLength})")
            if (-not $expectedMatch.Success) { continue }
            $expectedHash = $expectedMatch.Groups[1].Value.ToUpperInvariant()
            $actualHash = (Get-FileHash -LiteralPath $imageItem.FullName -Algorithm $algorithm).Hash.ToUpperInvariant()
            $matchesHash = $expectedHash -eq $actualHash
            $hashResults.Add("$algorithm $(if ($matchesHash) { 'совпадает' } else { 'НЕ СОВПАДАЕТ' })")
            if (-not $matchesHash) {
                Add-Finding -Category "Контрольная сумма $algorithm" -Priority 'Высокий' -Confidence 'Высокий' `
                    -Evidence "Ожидалось $expectedHash по файлу $sidecarPath; получено $actualHash." `
                    -Description 'Вычисленная контрольная сумма не совпала со значением из сопроводительного файла.' `
                    -NextStep 'Проверь, что выбран исходный сегмент и правильный сопроводительный файл; сохрани оба значения и не меняй источник.'
            }
        }
        if ($hashResults.Count -gt 0) { $sidecarHashNote = "$($hashResults -join '; ') (по значениям из $sidecarPath)." }
    }
}

$imageInfoPath = Join-Path $fullOutputPath 'Сведения_об_образе.txt'
$imageInfoExit = 0
if ($isLogicalDirectory) {
    'Источник является логической папкой, это не секторный образ; tsk_imageinfo не применяется.' | Set-Content -LiteralPath $imageInfoPath -Encoding UTF8
}
else {
    $imageInfoExit = Invoke-ReadOnlyTool -Executable $imageInfoExe -Arguments (Add-ImageOptions @($imageFiles[0].FullName)) -OutputFile $imageInfoPath
}
$imageInfoText = Get-Content -LiteralPath $imageInfoPath -Raw -Encoding UTF8
$unsupportedAd1 = $imageInfoText -match '(?is)TSK Support:\s*No\s*\(Custom Content Image \(AD1\)\)'
if ($unsupportedAd1) {
    Add-Finding -Category 'Формат AD1 не поддерживается' -Priority 'Средний' -Confidence 'Высокий' `
        -Evidence 'Sleuth Kit сообщил: TSK Support: No (Custom Content Image (AD1)). Контейнер и его содержимое не были разобраны.' `
        -Description 'Получен только SHA-256 контейнера. Нулевое число разделов или совпадений эвристик здесь не является результатом анализа файлов.' `
        -NextStep 'Открой копию в инструменте, который явно поддерживает FTK AD1, и экспортируй выбранные файлы в отдельную рабочую папку; затем передай папку этому скрипту с -ImageType logical.'
}
if ($imageInfoExit -ne 0) {
    Add-Finding -Category 'Формат образа' -Priority 'Средний' -Confidence 'Средний' `
        -Evidence "tsk_imageinfo завершился с кодом $imageInfoExit. См. Сведения_об_образе.txt." `
        -Description 'Инструмент не смог уверенно прочитать метаданные образа.' `
        -NextStep 'Проверь расширение, полноту сегментов и попробуй открыть копию образа в Autopsy.'
}

$partitionTablePath = Join-Path $fullOutputPath 'Таблица_разделов.txt'
$mmlsExit = 0
if ($isLogicalDirectory) {
    'Логическая папка не содержит таблицу разделов. Список файлов получен через fls -i logical.' | Set-Content -LiteralPath $partitionTablePath -Encoding UTF8
}
else {
    $mmlsExit = Invoke-ReadOnlyTool -Executable $mmlsExe -Arguments (Add-ImageOptions $imageArguments) -OutputFile $partitionTablePath
}
$partitions = [System.Collections.Generic.List[object]]::new()
foreach ($line in (Get-Content -LiteralPath $partitionTablePath -Encoding UTF8)) {
    if ($line -match '^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$' -and
        $Matches[2] -ne 'Meta' -and $Matches[2] -notmatch '^-+$' -and $Matches[6] -notmatch '^Unallocated$') {
        $partitions.Add([pscustomobject]@{
            Slot = $Matches[1]
            Type = $Matches[2]
            StartSector = [long]$Matches[3]
            EndSector = [long]$Matches[4]
            LengthSectors = [long]$Matches[5]
            Description = $Matches[6]
        })
    }
}
if (-not $isLogicalDirectory -and ($mmlsExit -ne 0 -or $partitions.Count -eq 0)) {
    Add-Finding -Category 'Таблица разделов' -Priority 'Низкий' -Confidence 'Средний' `
        -Evidence "mmls завершился с кодом $mmlsExit или не распознал разделы. См. Таблица_разделов.txt." `
        -Description 'Таблицу разделов не удалось автоматически разобрать; это бывает у логического образа, повреждённого или неподдерживаемого формата.' `
        -NextStep 'Открой копию в Autopsy и проверь формат/сегменты. Не меняй исходный образ.'
}

if ($Offset -ge 0) {
    $partitions.Clear()
    $partitions.Add([pscustomobject]@{
        Slot = 'ручное'; Type = 'manual'; StartSector = $Offset; EndSector = 0
        LengthSectors = 0; Description = 'Смещение из параметра -Offset (сектора)'
    })
}

$filesystemSummaries = [System.Collections.Generic.List[object]]::new()
$listingFiles = [System.Collections.Generic.List[string]]::new()
if ($partitions.Count -gt 0) {
    foreach ($partition in $partitions) {
        $slotName = $partition.Slot.PadLeft(3, '0')
        $fsPath = Join-Path $fullOutputPath "ФС_раздел_$slotName.txt"
        $fsExit = Invoke-ReadOnlyTool -Executable $fsstatExe -Arguments (Add-ImageOptions (@('-o', [string]$partition.StartSector) + $imageArguments)) -OutputFile $fsPath
        $fsText = Get-Content -LiteralPath $fsPath -Raw -Encoding UTF8
        $fsName = 'Не определена автоматически'
        if ($fsText -match '(?im)^File System Type:\s*(.+)$') { $fsName = $Matches[1].Trim() }
        elseif ($fsText -match '(?im)^File System:\s*(.+)$') { $fsName = $Matches[1].Trim() }
        $filesystemSummaries.Add([pscustomobject]@{ Slot = $slotName; StartSector = $partition.StartSector; Description = $partition.Description; FileSystem = $fsName; ExitCode = $fsExit; Output = $fsPath })

        $listingPath = Join-Path $fullOutputPath "Список_файлов_раздел_$slotName.txt"
        $flsOptions = @('-r', '-p', '-l', '-o', [string]$partition.StartSector)
        if ($TimeZone) { $flsOptions += @('-z', $TimeZone) }
        if ($MetadataOnly) { $flsOptions = @('-p', '-l', '-o', [string]$partition.StartSector); if ($TimeZone) { $flsOptions += @('-z', $TimeZone) } }
        $flsExit = Invoke-ReadOnlyTool -Executable $flsExe -Arguments (Add-ImageOptions ($flsOptions + $imageArguments)) -OutputFile $listingPath
        $listingFiles.Add($listingPath)
        if ($flsExit -ne 0) {
            Add-Finding -Category 'Список файлов' -Priority 'Средний' -Confidence 'Средний' `
                -Evidence "fls завершился с кодом $flsExit для раздела $slotName. См. $([IO.Path]::GetFileName($listingPath))." `
                -Description 'Не удалось полностью перечислить файлы раздела.' `
                -NextStep 'Проверь раздел в Autopsy; при необходимости укажи корректный тип образа и секторный размер.'
        }
    }
}
else {
    $fsPath = Join-Path $fullOutputPath 'ФС_без_таблицы_разделов.txt'
    if ($isLogicalDirectory) {
        'Для логической папки файловая система и секторная таблица недоступны. Используйте список путей fls.' | Set-Content -LiteralPath $fsPath -Encoding UTF8
        $fsExit = 0
    }
    else {
        $fsExit = Invoke-ReadOnlyTool -Executable $fsstatExe -Arguments (Add-ImageOptions $imageArguments) -OutputFile $fsPath
    }
    $listingPath = Join-Path $fullOutputPath 'Список_файлов_без_таблицы_разделов.txt'
    $flsOptions = @('-r', '-p', '-l'); if ($TimeZone) { $flsOptions += @('-z', $TimeZone) }; if ($MetadataOnly) { $flsOptions = @('-p', '-l'); if ($TimeZone) { $flsOptions += @('-z', $TimeZone) } }
    $flsExit = Invoke-ReadOnlyTool -Executable $flsExe -Arguments (Add-ImageOptions ($flsOptions + $imageArguments)) -OutputFile $listingPath
    $listingFiles.Add($listingPath)
    if ($flsExit -ne 0) {
        Add-Finding -Category 'Список файлов' -Priority 'Средний' -Confidence 'Средний' `
            -Evidence "fls завершился с кодом $flsExit. См. $([IO.Path]::GetFileName($listingPath))." `
            -Description 'Не удалось автоматически перечислить файлы образа.' `
            -NextStep 'Открой копию в Autopsy и проверь поддержку формата.'
    }
    $sourceDescription = if ($isLogicalDirectory) { 'Логическая папка, без секторного образа' } else { 'Образ без автоматически распознанной таблицы разделов' }
    $fsDescription = if ($isLogicalDirectory) { 'Не применяется к логическому источнику' } else { 'Проверь файл ФС_без_таблицы_разделов.txt' }
    $filesystemSummaries.Add([pscustomobject]@{ Slot = '—'; StartSector = 0; Description = $sourceDescription; FileSystem = $fsDescription; ExitCode = $fsExit; Output = $fsPath })
}

$rules = @(
    [pscustomobject]@{ Name='Автозагрузка пользователя'; Regex='(?i)(^|[\\/\s:])(Users|Documents and Settings)/[^/\\]+/(AppData/Roaming|Application Data)/Microsoft/Windows/Start Menu/Programs/Startup/'; Priority='Высокий'; Confidence='Средний'; Why='Файл находится в папке автозагрузки пользователя.'; Next='Проверь тип файла, временные метки, подпись и связь с Prefetch/Amcache/реестром.' },
    [pscustomobject]@{ Name='Задача планировщика'; Regex='(?i)(^|[\\/\s:])(Windows/System32/Tasks|Windows/SysWOW64/Tasks)/'; Priority='Средний'; Confidence='Низкий'; Why='Найден файл задачи планировщика; легитимные задачи встречаются часто.'; Next='Изучи XML задачи и проверь имя запускаемого файла, пользователя, триггер и время создания.' },
    [pscustomobject]@{ Name='Исполняемый файл в доступном для записи каталоге'; Regex='(?i)(^|[\\/\s:])(Users/Public|ProgramData|Windows/Temp|Users/[^/\\]+/AppData/(Local|Roaming)|Temp)/[^\r\n]*\.(exe|dll|scr|com|sys|ps1|psm1|vbs|vbe|js|jse|hta|bat|cmd)'; Priority='Средний'; Confidence='Низкий'; Why='Исполняемый файл или скрипт находится в каталоге, куда часто может записывать обычный пользователь.'; Next='Проверь подпись, SHA-256, соседние файлы, Prefetch, журналы запуска и родительскую задачу/службу.' },
    [pscustomobject]@{ Name='Скрипт в веб-каталоге'; Regex='(?i)(^|[\\/\s:])(inetpub/wwwroot|www/html|htdocs)/[^\r\n]*\.(aspx|ashx|asp|php|jsp|jspx)'; Priority='Высокий'; Confidence='Низкий'; Why='Скрипт в веб-каталоге может быть легитимным приложением или веб-шеллом.'; Next='Сверь файл с известной версией сайта, проверь содержимое в Autopsy и сопоставь с HTTP-журналами.' },
    [pscustomobject]@{ Name='Название известного инструмента администрирования/сбора'; Regex='(?i)(mimikatz|procdump|psexec|rclone|nc\.exe|ncat\.exe|chisel|ligolo|frpc|ngrok)'; Priority='Средний'; Confidence='Низкий'; Why='Имя совпало с часто встречающимся инструментом двойного назначения; само совпадение не доказывает вредоносность.'; Next='Проверь SHA-256, подпись, полный путь, время появления и подтверждение в журналах/Prefetch.' },
    [pscustomobject]@{ Name='Двойное расширение файла'; Regex='(?i)\.(pdf|docx|xlsx|jpg|jpeg|png|txt|rtf)\.(exe|scr|com|bat|cmd|js|vbs|hta)(\s|$)'; Priority='Средний'; Confidence='Низкий'; Why='Двойное расширение может маскировать исполняемый файл под документ или изображение.'; Next='Проверь реальный тип по сигнатуре файла, его содержимое, хэш и исходный путь.' },
    [pscustomobject]@{ Name='Возможная копия базы учётных данных или дамп памяти'; Regex='(?i)(^|[/\\\s:])(lsass[^/\\]*\.(dmp|mdmp)|ntds\.dit|sam\.(save|bak)|security\.(save|bak))(\s|$)'; Priority='Средний'; Confidence='Низкий'; Why='Имя соответствует файлу, который может содержать учётные данные; также это может быть штатная резервная копия или учебный артефакт.'; Next='Проверь полный путь, время появления, владельца и доступ к файлу; не открывай и не публикуй его содержимое.' },
    [pscustomobject]@{ Name='Удалённый исполняемый файл или скрипт'; Regex='(?i)^.*\*.*\.(exe|dll|scr|com|sys|ps1|vbs|js|hta|bat|cmd)(\s|$)'; Priority='Средний'; Confidence='Низкий'; Why='Запись помечена Sleuth Kit как удалённая и имеет исполняемое расширение.'; Next='Проверь возможность восстановления в Autopsy/TSK, затем хэш и содержимое только на рабочей копии.' }
)

$automaticFindings = 0
foreach ($listingPath in $listingFiles) {
    foreach ($line in (Get-Content -LiteralPath $listingPath -Encoding UTF8)) {
        foreach ($rule in $rules) {
            if ($line -match $rule.Regex) {
                Add-Finding -Category $rule.Name -Priority $rule.Priority -Confidence $rule.Confidence `
                    -Evidence ("{0}: {1}" -f [IO.Path]::GetFileName($listingPath), $line.Trim()) `
                    -Description $rule.Why -NextStep $rule.Next
                $automaticFindings++
                break
            }
        }
        if ($automaticFindings -ge $MaxFindings) { break }
    }
    if ($automaticFindings -ge $MaxFindings) { break }
}

$findings | Export-Csv -LiteralPath (Join-Path $fullOutputPath 'Кандидаты_на_проверку.csv') -NoTypeInformation -Encoding UTF8
$imageTable = ($imageRecords | ForEach-Object {
    "| $(ConvertTo-SafeMarkdown $_.ИмяФайла) | $($_.РазмерБайт) | $(if ($_.SHA256) { $_.SHA256 } else { 'пропущен' }) | $($_.ИзменёнUTC) |"
}) -join "`r`n"
$partitionTable = ($partitions | ForEach-Object {
    "| $($_.Slot) | $($_.StartSector) | $($_.LengthSectors) | $(ConvertTo-SafeMarkdown $_.Description) |"
}) -join "`r`n"
$fsTable = ($filesystemSummaries | ForEach-Object {
    "| $($_.Slot) | $($_.StartSector) | $(ConvertTo-SafeMarkdown $_.FileSystem) | $($_.ExitCode) |"
}) -join "`r`n"
$findingMarkdown = if ($findings.Count -eq 0) {
    'По простым правилам анализа путей автоматических совпадений не найдено. Это не доказывает отсутствие компрометации.'
} else {
    ($findings | ForEach-Object {
        "### $($_.Категория) — приоритет $($_.Приоритет)`r`n`r`n- Уверенность эвристики: $($_.Уверенность)`r`n- Наблюдение: $($_.Описание)`r`n- Артефакт: ``$($_.Доказательство)```r`n- Что проверить: $($_.СледующийШаг)"
    }) -join "`r`n`r`n"
}
$hashNote = if ($isLogicalDirectory) { 'SHA-256 для всех файлов логического источника этим скриптом не рассчитывается.' } elseif ($SkipHash) { 'Хэширование пропущено параметром -SkipHash.' } else { 'SHA-256 вычислен для каждого указанного сегмента.' }
$imageTypeNote = if ($unsupportedAd1) { 'AD1 (Sleuth Kit сообщает, что формат не поддерживается)' } elseif ($ImageType -eq 'Auto') { 'Автоопределение Sleuth Kit' } else { $ImageType }
$sectorNote = "Размер сектора: $SectorSize байт; смещение: $(if ($Offset -ge 0) { $Offset } else { 'авто/по таблице разделов' }) секторов; часовой пояс: $(if ($TimeZone) { $TimeZone } else { 'не задан' })."
$timeZoneReportNote = if ($TimeZone) { "Часовой пояс передан в fls: $TimeZone. Проверь правильность и учёт летнего времени." } else { 'Часовой пояс fls не задан; проверь временные метки в Autopsy.' }
$logicalSourceNote = if ($isLogicalDirectory) { 'Логический сбор не содержит свободного пространства и удалённых секторов; отдельные файлы не хэшируются этим скриптом.' } else { '' }
$reportPath = Join-Path $fullOutputPath 'Первичный_отчёт_по_образу.md'
$report = @"
# Первичный отчёт по образу диска

## Дело

- Название: $CaseName
- Дата формирования (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))
- Образ для анализа: ``$resolvedImage``
- Метод: чтение образа средствами Sleuth Kit; исходный образ не монтировался и не изменялся.
- Формат: $imageTypeNote. $sectorNote
- Режим перечисления файлов: $(if ($MetadataOnly) { 'только верхний уровень, без рекурсии' } else { 'рекурсивно' })
- Хэширование: $hashNote
- Сверка хэшей по сопроводительному файлу: $sidecarHashNote
- $timeZoneReportNote
- Ограничение: автоматические совпадения по именам и путям являются только подсказками для ручной проверки.
$(if ($isLogicalDirectory) { '- Источник — логический сбор файлов: свободное пространство, нераспределённые сектора и удалённые данные отсутствуют.' })

## Сегменты и контрольные суммы

| Файл | Размер, байт | SHA-256 | Изменён UTC |
|---|---:|---|---|
$imageTable

## Таблица разделов

См. полный вывод: ``Таблица_разделов.txt``. Код завершения mmls: $mmlsExit.

| Слот | Начальный сектор | Длина, секторов | Описание |
|---|---:|---:|---|
$partitionTable

## Файловые системы

| Слот | Начальный сектор | Определённая файловая система | Код |
|---|---:|---|---:|
$fsTable

Подробные сведения: файлы ``ФС_раздел_*.txt``. Полные перечни путей и временных меток: ``Список_файлов_*.txt``.

## Кандидаты на проверку

Совпадений эвристик по путям/именам: $automaticFindings. Предупреждений о чтении/формате: $($findings.Count - $automaticFindings). Лимит сбора эвристик: $MaxFindings.

$findingMarkdown

## Следующие действия аналитика

1. $(if ($unsupportedAd1) { 'Текущий скрипт не разбирает контейнер AD1. Импортируй копию в инструмент с явной поддержкой FTK AD1; после экспорта файлов передай папку скрипту как -ImageType logical.' } else { 'Открой образ в Autopsy; выбери правильный часовой пояс, проверь целостность источника и дождись построения временной шкалы.' })
2. Сверь подозрительные пути с содержимым файла, временными метками, владельцем, подписью и SHA-256. Имя и расположение сами по себе не доказывают вредоносность.
3. Проверь кусты реестра через Registry Explorer, события и артефакты Windows через инструменты Eric Zimmerman, сопоставь с Prefetch, LNK, Amcache, USN/MFT и журналами.
4. Не запускай найденные программы. Экспортируй только копии в отдельную рабочую папку; динамический анализ выполняй только в изолированной среде соревнования.
5. Заполни временную шкалу, область воздействия, факты/гипотезы и ограничения в отдельном отчёте.

## Границы автоматического анализа

Скрипт определяет метаданные образа, таблицу разделов, сводки файловых систем, перечень имён и совпадения по нескольким эвристикам путей/имён. Он не читает содержимое каждого файла, не разбирает кусты реестра внутри образа, не определяет факт запуска, не анализирует RAM и не выносит вердикт о компрометации. Отсутствие совпадений не означает, что образ чист.
"@
Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8

# Отдельная HTML-копия удобна для просмотра в любом браузере без интернета.
$encode = { param([AllowNull()][string]$Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }
$imageRowsHtml = foreach ($record in $imageRecords) {
    $hashValue = if ($record.SHA256) { $record.SHA256 } else { 'Пропущен' }
    "<tr><td>$(& $encode $record.ИмяФайла)</td><td>$($record.РазмерБайт)</td><td><code>$hashValue</code></td><td>$(& $encode $record.ИзменёнUTC)</td></tr>"
}
$partitionRowsHtml = foreach ($partition in $partitions) {
    "<tr><td>$($partition.Slot)</td><td>$($partition.StartSector)</td><td>$($partition.LengthSectors)</td><td>$(& $encode $partition.Description)</td></tr>"
}
$filesystemRowsHtml = foreach ($summary in $filesystemSummaries) {
    "<tr><td>$(& $encode $summary.Slot)</td><td>$($summary.StartSector)</td><td>$(& $encode $summary.FileSystem)</td><td>$($summary.ExitCode)</td></tr>"
}
$findingCardsHtml = if ($findings.Count -eq 0) {
    '<p class="quiet">По простым правилам анализа путей совпадений не найдено. Это не доказывает отсутствие компрометации.</p>'
} else {
    foreach ($finding in $findings) {
        "<article><h3>$(& $encode $finding.Категория) <span>$(& $encode $finding.Приоритет)</span></h3><p><b>Уверенность:</b> $(& $encode $finding.Уверенность)</p><p><b>Наблюдение:</b> $(& $encode $finding.Описание)</p><p><b>Артефакт:</b><br><code>$(& $encode $finding.Доказательство)</code></p><p><b>Что проверить:</b> $(& $encode $finding.СледующийШаг)</p></article>"
    }
}
$htmlPath = Join-Path $fullOutputPath 'Первичный_отчёт_по_образу.html'
$html = @"
<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Первичный отчёт по образу диска</title>
<style>
body{font:16px/1.55 Segoe UI,Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 22px;color:#1d2733;background:#f5f7fa}h1,h2{color:#163d60}h1{border-bottom:3px solid #5c94c4;padding-bottom:12px}section,article{background:#fff;border:1px solid #d7e0e8;border-radius:8px;padding:16px 20px;margin:16px 0}article{border-left:5px solid #d89a37}article h3{margin-top:0}article h3 span{font-size:.8em;color:#72500b;background:#fff1ce;padding:3px 8px;border-radius:10px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #ccd6df;padding:8px;text-align:left;vertical-align:top}th{background:#e6eff7}code{overflow-wrap:anywhere;color:#783d24}.quiet{color:#5d6872;background:#fff8e4;padding:12px;border-radius:6px}.note{border-left:4px solid #548bb8;padding-left:12px}
</style></head><body>
<h1>Первичный отчёт по образу диска</h1>
<section><h2>Дело</h2><p><b>Название:</b> $(& $encode $CaseName)<br><b>Дата формирования UTC:</b> $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))<br><b>Образ/источник:</b> <code>$(& $encode $resolvedImage)</code><br><b>Метод:</b> чтение средствами Sleuth Kit; исходник не монтировался и не изменялся.<br><b>SHA-256:</b> $(& $encode $hashNote)</p><p class="note">$(& $encode $timeZoneReportNote) $(& $encode $logicalSourceNote) Совпадения по путям и именам требуют ручной проверки.</p></section>
<section><h2>Сегменты и контрольные суммы</h2><table><tr><th>Файл</th><th>Размер, байт</th><th>SHA-256</th><th>Изменён UTC</th></tr>$($imageRowsHtml -join "`n")</table></section>
<section><h2>Разделы</h2><p>Полный вывод: <code>Таблица_разделов.txt</code>; код завершения mmls: $mmlsExit.</p><table><tr><th>Слот</th><th>Начальный сектор</th><th>Длина, секторов</th><th>Описание</th></tr>$($partitionRowsHtml -join "`n")</table></section>
<section><h2>Файловые системы</h2><table><tr><th>Слот</th><th>Начальный сектор</th><th>Определение</th><th>Код</th></tr>$($filesystemRowsHtml -join "`n")</table><p>Полные выводы лежат в файлах <code>ФС_раздел_*.txt</code> и <code>Список_файлов_*.txt</code>.</p></section>
<section><h2>Кандидаты на проверку</h2><p>Совпадений эвристик: $automaticFindings. Предупреждений чтения/формата: $($findings.Count - $automaticFindings).</p>$($findingCardsHtml -join "`n")</section>
<section><h2>Дальнейшие шаги</h2><ol><li>$(if ($unsupportedAd1) { 'Текущий скрипт не разбирает контейнер AD1. Импортируй копию в инструмент с явной поддержкой FTK AD1.' } else { 'Открой образ в Autopsy, проверь временную зону и целостность источника.' })</li><li>Сверь каждый путь с содержимым файла, хэшем, подписью, Prefetch, Amcache, реестром и журналами.</li><li>Используй Registry Explorer и инструменты Eric Zimmerman для анализа экспортированных артефактов.</li><li>Не запускай найденные файлы; работай с копиями в отдельной папке.</li></ol><p class="quiet">Скрипт не читает содержимое каждого файла, не разбирает кусты реестра, не определяет факт запуска и не выносит вердикт о компрометации. Отсутствие совпадений не означает, что образ чист.</p></section>
</body></html>
"@
Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

Write-Host "Первичный отчёт создан: $reportPath"
Write-Host "Удобная для просмотра HTML-версия: $htmlPath"
Write-Host "Файлов-сегментов: $($imageFiles.Count); разделов: $($partitions.Count); совпадений эвристик: $automaticFindings"
Write-Host "Все результаты сохранены отдельно от исходного образа: $fullOutputPath"
