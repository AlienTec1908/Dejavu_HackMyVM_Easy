# Dejavu - HackMyVM (Easy)

![Dejavu.png](Dejavu.png)

## Übersicht

*   **VM:** Dejavu
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Dejavu)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 27. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Dejavu_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Easy"-Challenge war es, Root-Zugriff auf der Maschine "Dejavu" zu erlangen. Die Enumeration des Webservers (Apache auf Ubuntu) deckte eine `info.php`-Datei und einen versteckten Pfad (`/S3cR3t/`) mit einer Upload-Funktion (`upload.php`) auf. Mittels `chankro.py` wurde eine Reverse-Shell-Payload (`rev.sh`) in eine `.phtml`-Datei umgewandelt und hochgeladen, was initialen Zugriff als Benutzer `www-data` ermöglichte. Als `www-data` wurde eine `sudo`-Regel entdeckt, die es erlaubte, `tcpdump` als Benutzer `robert` auszuführen. Durch das Mitschneiden des Loopback-Traffics wurde ein FTP-Login von `robert` auf `localhost` mit Klartext-Passwort (`9737bo0hFx4`) abgefangen. Nach dem SSH-Login als `robert` wurde festgestellt, dass eine veraltete Version von `exiftool` (12.23) installiert war. Diese Version ist anfällig für CVE-2021-22204. Durch Ausführen von `sudo -u root exiftool` auf eine präparierte DJVU-Datei (erstellt mit einem öffentlichen Exploit-Skript) wurde eine Reverse Shell als `root` erlangt und die Root-Flag gelesen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `chankro.py`
*   `nc` (netcat)
*   `python3`
*   `sudo` (auf Zielsystem)
*   `tcpdump`
*   `ssh`
*   `exiftool` (als Exploit-Vektor)
*   `git`
*   `nano` (oder anderer Texteditor)
*   Standard Linux-Befehle (`vi`, `ls`, `cat`, `id`, `export`, `stty`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Dejavu" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.113`, Hostname `dejavu.hmv`).
    *   `nmap`-Scan identifizierte SSH (22/tcp) und Apache (80/tcp).
    *   `gobuster` auf Port 80 fand `/info.php` (PHP-Info-Seite) und einen versteckten Pfad `/S3cR3t/` (vermutlich aus `info.php` extrahiert).
    *   Im Verzeichnis `/S3cR3t/` wurden das Unterverzeichnis `files` und die Datei `upload.php` gefunden.

2.  **Initial Access (als www-data via PHP Upload RCE):**
    *   Eine Bash-Reverse-Shell-Payload (`rev.sh`) wurde erstellt.
    *   `chankro.py` wurde verwendet, um `rev.sh` in eine `.phtml`-Datei (`ben.phtml`) umzuwandeln, die vermutlich Upload-Filter umgeht.
    *   Die Datei `ben.phtml` wurde über `upload.php` in das Verzeichnis `/S3cR3t/files/` hochgeladen (Upload-Schritt nicht im Log, aber impliziert).
    *   Durch Aufrufen von `http://dejavu.hmv/S3cR3t/files/ben.phtml` wurde die Payload ausgeführt und eine Reverse Shell als Benutzer `www-data` etabliert.

3.  **Privilege Escalation (von `www-data` zu `robert`):**
    *   Als `www-data` wurde mittels `sudo -l` entdeckt, dass `/usr/sbin/tcpdump` als Benutzer `robert` ohne Passwort ausgeführt werden darf.
    *   `sudo -u robert tcpdump -i lo port ftp` wurde gestartet, um den FTP-Verkehr auf dem Loopback-Interface mitzuschneiden.
    *   Ein lokaler FTP-Login des Benutzers `robert` wurde abgefangen, wodurch das Passwort `9737bo0hFx4` im Klartext offenbart wurde.
    *   Ein SSH-Login als `robert` mit dem Passwort `9737bo0hFx4` war erfolgreich. Die User-Flag wurde gelesen.

4.  **Privilege Escalation (von `robert` zu `root` via Exiftool CVE-2021-22204):**
    *   Als `robert` wurde die Version von `exiftool` als 12.23 identifiziert, die anfällig für CVE-2021-22204 ist.
    *   Ein Exploit-Skript für CVE-2021-22204 wurde von GitHub geklont und so modifiziert, dass es eine Reverse Shell zum Angreifer aufbaut.
    *   Das Skript generierte eine bösartige DJVU-Datei (`exploit.djvu`).
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet.
    *   Auf dem Zielsystem wurde `sudo -u root exiftool ./exploit.djvu` ausgeführt.
    *   Dies löste die Schwachstelle aus und etablierte eine Reverse Shell als `root`.

## Wichtige Schwachstellen und Konzepte

*   **PHP Info Disclosure:** Die `/info.php`-Seite enthüllte sensible Informationen, darunter (vermutlich) den versteckten Pfad `/S3cR3t/`.
*   **Unsichere Datei-Upload-Funktion:** Ermöglichte das Hochladen einer `.phtml`-Datei, die serverseitig ausgeführt wurde (RCE).
*   **Verwendung von `chankro.py`:** Diente zur Umgehung von Upload-Filtern durch Umwandlung einer Shell-Payload in eine `.phtml`-Datei.
*   **Unsichere `sudo`-Regel (tcpdump):** Erlaubte `www-data` das Ausführen von `tcpdump` als `robert`, was zum Abfangen von Klartext-Credentials führte.
*   **Klartext-Protokolle (FTP auf Loopback):** Ein lokaler Prozess verwendete FTP mit Klartext-Passwörtern.
*   **Veraltete Software / Bekannte CVE (Exiftool CVE-2021-22204):** Eine verwundbare Version von `exiftool` ermöglichte RCE.
*   **Unsichere `sudo`-Regel (Exiftool):** (Vermutlich vorhanden, da `sudo -u root exiftool` funktionierte) Das Ausführen von `exiftool` als Root durch einen weniger privilegierten Benutzer ermöglichte die Ausnutzung der CVE für Root-Zugriff.

## Flags

*   **User Flag (`/home/robert/user.txt`):** `HMV{c8b75037150fbdc49f6c941b72db0d7c}`
*   **Root Flag (`/root/r0ot.tXt`):** `HMV{c62d75d636f66450980dca2c4a3457d8}`

## Tags

`HackMyVM`, `Dejavu`, `Easy`, `Web`, `Apache`, `PHP Info`, `File Upload`, `RCE`, `chankro`, `sudo`, `tcpdump`, `Credentials Harvesting`, `Exiftool`, `CVE-2021-22204`, `Privilege Escalation`, `Linux`
