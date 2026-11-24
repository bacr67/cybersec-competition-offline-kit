# Шпаргалка по Volatility 3

Локальные пакеты wheel в `Volatility3-wheelhouse`. Установка см. `Общие_справочники\Обзор_справочников.md`. На конкурсе сохраняйте вывод в отдельные файлы и включайте `-o` для каталогов дампа. Из корня комплекта сначала перейдите в каталог модуля:

```powershell
Set-Location .\Г_Форензика_и_ВПО
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.info
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.pslist
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.pstree
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.cmdline
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.netscan
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.malfind
.\.venv\Scripts\vol.exe -f .\evidence\mem.raw windows.dlllist --pid <PID>
```

Ищите несоответствия: процесс без ожидаемого parent, image path в temp/user profile, странная command line, удалённый процесс, необычная связь PID↔socket, executable private memory. Ни один плагин сам не доказывает компрометацию. Для windows.info и других Windows plugins могут понадобиться PDB symbols; подготовьте нужный кеш для соответствующей сборки Windows до полного офлайна.
