# Шпаргалка по Ghidra

Запуск и JDK — в `Г_Форензика_и_ВПО/НАЧНИ_ЗДЕСЬ.md`. Import File → выбрать копию образца → Auto Analyze → Listing/Decompiler.

Искать: entry point, strings и ссылки на строки, imports, сетевые/файловые API, registry/process/thread APIs, suspicious constants, ресурсы и sections. Открывайте Xrefs, прослеживайте вызовы и ветвления. Псевдокод — гипотеза; подтвердите типы/аргументы в Listing. Фиксируйте адреса функций и артефакты.
