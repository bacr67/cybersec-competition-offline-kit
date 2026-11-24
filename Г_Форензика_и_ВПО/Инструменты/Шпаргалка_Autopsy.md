# Шпаргалка по Autopsy

1. Открыть `Инструменты\Autopsy\autopsy-4.23.1\bin\autopsy64.exe`.
2. New Case → case name/base directory на рабочем диске → Add Data Source → выданный E01/raw/диск/папка.
3. Выбрать ingest modules по времени и объёму (типовые: Recent Activity, File Type Identification, Hash Lookup если база есть, Embedded File Extractor, Keyword Search).
4. Проверять Timeline, Results, File Views, Web/OS artifacts; открывать исходный файл/метаданные, сохранять путь и время.
5. Экспорт evidence/CSV и отчёт; сохранить базу и выходные данные отдельно от оригинального образа.

Если времени мало: быстро проверить пользовательские файлы, downloads, LNK, Prefetch, браузер, email, scheduled tasks/services и временную линию. Ложный hit hash/keyword требует ручной проверки.
