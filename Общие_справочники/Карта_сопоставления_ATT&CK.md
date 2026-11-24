# MITRE ATT&CK: быстрая карта

## Быстрая карта MITRE ATT&CK для сопоставления

Используйте таблицу как указатель, а не как готовый вывод расследования: сначала найдите конкретный след, затем сопоставьте наблюдаемое поведение с техникой. Сам факт наличия уязвимости или команды ещё не доказывает, что атакующий применил эту технику. Если нужная телеметрия отсутствует, пишите «неизвестно / данных недостаточно».

| Модуль | Техника ATT&CK (ID) | Какие следы искать | Где смотреть / инструмент |
|---|---|---|---|
| A, B | Exploit Public-Facing Application (T1190) | Запрос к уязвимому endpoint, ошибка/аномальный ответ, затем запуск процесса или соединение сервера | HTTP/WAF/app логи, PCAP, EDR; уязвимый скан сам по себе эксплуатацию не подтверждает |
| A, B | Phishing: Spearphishing Attachment (T1566.001) | Письмо и вложение, доставка, открытие файла, дочерний процесс Office/почтового клиента | Заголовки письма, почтовые логи, LNK/Prefetch, EVTX/Sysmon; EvtxECmd, PECmd |
| A, B | Phishing: Spearphishing Link (T1566.002) | Ссылка в письме/сообщении, переход, DNS/HTTP запрос, вход или загрузка после перехода | Заголовки/URL, proxy, DNS, PCAP, браузерная история; Wireshark, Autopsy |
| B, D | User Execution: Malicious File (T1204.002) | Файл получен и запущен пользователем; необычный parent-child процесс, LNK или Prefetch | EVTX/Sysmon, Prefetch, LNK, Downloads; EvtxECmd, PECmd, LECmd, Autopsy |
| B, C, D | PowerShell (T1059.001) | powershell.exe/pwsh, подозрительная командная строка, encoded command, script block | Security 4688, Sysmon 1, PowerShell 4103/4104; EvtxECmd, SIEM |
| B, C, D | Windows Command Shell (T1059.003) | cmd.exe и команды из необычного родителя/каталога, цепочка запуска | 4688/Sysmon 1, process tree, Prefetch; EvtxECmd, Volatility |
| B, C, D | Scheduled Task (T1053.005) | Новая/изменённая задача, необычный action/path/user/time | Security 4698/4702, Task Scheduler Operational, Tasks и TaskCache; EvtxECmd, Registry Explorer, RECmd |
| B, C, D | Registry Run Keys / Startup Folder (T1547.001) | Новое значение Run/RunOnce или файл/ярлык в Startup, ссылка на необычный путь | SOFTWARE/NTUSER.DAT, Startup, Amcache, LNK; Registry Explorer/RECmd, Autopsy |
| B, C, D | Windows Service (T1543.003) | Служба с новым именем, бинарником из Temp/AppData, необычным аккаунтом или путём | SYSTEM hive\Services, события 7045/4697, 4688; Registry Explorer, EvtxECmd |
| B, C, D | OS Credential Dumping: LSASS Memory (T1003.001) | Доступ/дамп LSASS, подозрительное открытие процесса или созданный dump-файл | Sysmon 10, EDR, Security 4688, файлы dump; EvtxECmd, Volatility; один доступ к LSASS требует контекста |
| B, C, D | Process Discovery (T1057) | tasklist/Get-Process и похожее перечисление процессов | Командная строка и PowerShell logs, Sysmon 1, RAM process tree; EvtxECmd, Volatility |
| B, C, D | System Information Discovery (T1082) | systeminfo, hostname, сведения об ОС и железе | 4688/Sysmon 1, PowerShell logs, RAM cmdline; EvtxECmd, Volatility |
| B, C, D | System Network Configuration Discovery (T1016) | ipconfig, route, netstat и похожие команды просмотра сети | 4688/Sysmon 1, PowerShell logs, консольные артефакты; EvtxECmd, Volatility |
| B, C, D | Ingress Tool Transfer (T1105) | Сетевой download вместе с появлением нового файла и последующим запуском | Proxy/DNS/PCAP, Downloads, MFT/USN, Prefetch, EDR; Wireshark, Autopsy, PECmd |
| B, C, D | Web Protocols (T1071.001) | Повторяющиеся HTTP(S) соединения, подозрительный домен/путь/периодичность | DNS/proxy/Firewall/PCAP; Wireshark; HTTPS содержимое без ключей обычно не видно |
| B, C, D | Remote Services: Remote Desktop Protocol (T1021.001) | Удалённый интерактивный вход, источник/учётка/время, успешные и неуспешные входы | Security 4624/4625 (тип входа 10), TerminalServices logs, сеть; EvtxECmd/SIEM |
| B, C, D | Remote Services: SMB/Windows Admin Shares (T1021.002) | SMB вход/доступ к шарам, удалённый запуск или перемещение файлов | Security 4624 (тип 3), 5140/5145 при аудите, Sysmon/Firewall; EvtxECmd/SIEM |
| B, C, D | Clear Windows Event Logs (T1685.005) | Security 1102, событие очистки канала, следы wevtutil или пропуск/обрыв журналирования | Security/System, EDR, централизованный SIEM; EvtxECmd. В старых шпаргалках ID может быть T1070.001 |
| B, C, D | File Deletion (T1070.004) | Удалённый файл/самоудаление, разрыв таймлайна или следы удаления | $MFT, $UsnJrnl, Recycle Bin, Prefetch/EDR; Autopsy, MFTECmd, RBCmd |
| B, C, D | Data Encrypted for Impact (T1486) | Массовая запись/переименование файлов, ransom note, резкий рост изменений | $MFT/$UsnJrnl, файловая система, EDR, события; Autopsy, MFTECmd, Timeline Explorer |

**Как пользоваться:** `наблюдение → подтверждающий артефакт → техника ATT&CK → уверенность`. Для модуль А уязвимости описывайте также через OWASP/CWE и CVSS; ATT&CK описывает поведение атакующего. ATT&CK ID могут обновляться — при доступном интернете сверяйте название на attack.mitre.org, а в офлайн-режиме указывайте версию/дату шпаргалки.

