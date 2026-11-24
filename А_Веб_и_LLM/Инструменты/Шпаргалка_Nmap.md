# Шпаргалка по Nmap

Запускайте только по разрешённым IP/доменам. `-oA prefix` сохраняет normal/XML/grepable результаты.

```powershell
nmap -Pn -n -sV --top-ports 1000 -oA .\work\nmap <IP>
nmap -Pn -n -p- -oA .\work\allports <IP>
nmap -Pn -sV -sC -p 22,80,443 -oN .\work\services.txt <IP>
nmap -sn <разрешённая-CIDR> -oN .\work\hosts.txt
```

`-Pn` пропускает ping discovery; `-n` выключает DNS lookup; `-sV` определяет версии; `-sC` стандартные NSE scripts; `-p-` все TCP порты; `-sn` host discovery. Сначала узкий scan, потом точечная проверка. Баннер ≠ доказанная версия/уязвимость. `-sC` может быть шумным; используйте если scope позволяет.
