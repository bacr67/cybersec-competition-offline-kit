# Шпаргалка по Sysinternals

Утилиты расположены рядом в `Sysinternals\`.

- `strings.exe -n 6 sample.exe` — читаемые ASCII/Unicode строки; индикатор, не вердикт.
- `sigcheck.exe -nobanner -a -h sample.exe` — подпись, версия и hash.
- `autorunsc.exe -accepteula -a * -c -h` — автозапуск в CSV (проверяйте подозрительные пути/подписи).
- Process Explorer: дерево процессов, родитель, подпись, DLL/handles.
- TCPView: PID ↔ соединение/порт.
- Procmon: фильтр по PID/path/operation для наблюдения активности в разрешённой среде.

Для offline evidence используйте копии; не удаляйте и не отключайте найденные записи до фиксации доказательств и разрешения организатора.
