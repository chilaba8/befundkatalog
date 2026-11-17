# befundkatalog

**Pentest- und Audit-Befunde auf Deutsch – frei verwendbar.**

Wer Sicherheitsberichte für Kunden in der Schweiz, Deutschland oder Österreich schreibt,
formuliert dieselben Befunde immer wieder neu. Öffentliche Sammlungen gibt es fast nur
auf Englisch. `befundkatalog` sammelt Befunde in verständlichem Deutsch: technisch für
den Informatiker und in einem Satz für die Geschäftsleitung.

> Status: 59 Befunde zu E-Mail, DNS, Web und offenen Diensten, sprachlich und fachlich
> geprüft (`status: geprueft`). Der Katalog wächst – Korrekturen und neue Befunde sind willkommen.

## Aufbau eines Befunds

Eine YAML-Datei pro Befund, z. B. [`befunde/email/DMARC-FEHLT.yaml`](befunde/email/DMARC-FEHLT.yaml):

| Feld | Inhalt |
|---|---|
| `id` | stabiler Schlüssel – identisch mit den IDs von [pruefstand](https://github.com/chilaba8/pruefstand) |
| `schweregrad` | kritisch · hoch · mittel · niedrig · info |
| `cwe` | passende CWE-Nummer (falls es eine gibt) |
| `titel` | Deutsch, Englisch, Spanisch |
| `geschaeftsleitung` | ein bis zwei Sätze ohne Fachbegriffe |
| `beschreibung`, `auswirkung`, `empfehlung` | technischer Text; `{domain}` wird beim Export ersetzt |
| `pruefen` | Befehl, mit dem sich die Behebung überprüfen lässt |
| `referenzen` | RFC, Normen, offizielle Dokumentation |

Die Texte sind in **Schweizer Schreibweise** (ss, «…») verfasst. Für Deutschland erzeugt der
Export mit `--sz` ß und „…“.

## Befunde

59 Befunde – E-Mail 31, DNS 9, Web 12, Netzwerk 7 – sortiert nach Kategorie und Schweregrad.

| Kategorie | ID | Titel | Schweregrad |
|---|---|---|---|
| E-Mail | SPF-ALL-OFFEN | SPF erlaubt allen Servern den Versand (+all / ?all) | kritisch |
| E-Mail | AEHNLICH-NEU-REGISTRIERT | Ähnliche Domain mit E-Mail kürzlich registriert | hoch |
| E-Mail | DMARC-FEHLT | Kein DMARC-Eintrag vorhanden | hoch |
| E-Mail | DMARC-MEHRFACH | Mehrere DMARC-Einträge vorhanden | hoch |
| E-Mail | DMARC-P-NONE | DMARC nur im Beobachtungsmodus (p=none) | hoch |
| E-Mail | DMARC-UNGUELTIG | DMARC-Eintrag ungültig | hoch |
| E-Mail | MX-OHNE-IP | Mailserver ohne IP-Adresse (MX nicht auflösbar) | hoch |
| E-Mail | SPF-FEHLT | Kein SPF-Eintrag vorhanden | hoch |
| E-Mail | SPF-ZU-VIELE-LOOKUPS | SPF überschreitet die Grenze von 10 DNS-Abfragen | hoch |
| E-Mail | AEHNLICH-EIGENE-ABGELAUFEN | Eigene Schutz-Domain abgelaufen | mittel |
| E-Mail | AEHNLICH-EIGENE-UNGESCHUETZT | Eigene Schutz-Domain ohne SPF/DMARC | mittel |
| E-Mail | AEHNLICH-MIT-MAIL | Ähnliche Domain mit E-Mail-Empfang registriert | mittel |
| E-Mail | DKIM-NICHT-GEFUNDEN | Kein DKIM-Schlüssel unter den üblichen Selektoren gefunden | mittel |
| E-Mail | DKIM-SCHWACH | DKIM-Schlüssel zu kurz (unter 2048 Bit) | mittel |
| E-Mail | DKIM-WIDERRUFEN | Nur widerrufene DKIM-Schlüssel gefunden | mittel |
| E-Mail | DMARC-PCT | DMARC gilt nur für einen Teil der E-Mails (pct < 100) | mittel |
| E-Mail | DMARC-SP-NONE | Subdomains nicht durch DMARC geschützt (sp=none) | mittel |
| E-Mail | DNSBL-GELISTET | Mailserver auf einer Spam-Sperrliste | mittel |
| E-Mail | MTASTS-MX-PASST-NICHT | MTA-STS-Richtlinie passt nicht zu den Mailservern | mittel |
| E-Mail | SPF-FEHLER | SPF-Eintrag fehlerhaft | mittel |
| E-Mail | SPF-OHNE-ALL | SPF-Eintrag ohne Abschluss («all» fehlt) | mittel |
| E-Mail | CLOUD-M365-NICHT-IM-SPF | Microsoft 365 eingerichtet, aber nicht im SPF | niedrig |
| E-Mail | DMARC-KEIN-RUA | Keine DMARC-Berichte (rua) konfiguriert | niedrig |
| E-Mail | MTASTS-FEHLT | Keine MTA-STS-Richtlinie für eingehende E-Mails | niedrig |
| E-Mail | MTASTS-NONE | MTA-STS ausgeschaltet («mode: none») | niedrig |
| E-Mail | MTASTS-RICHTLINIE-FEHLT | MTA-STS angekündigt, Richtlinie nicht abrufbar | niedrig |
| E-Mail | MTASTS-TESTING | MTA-STS nur im Testmodus («mode: testing») | niedrig |
| E-Mail | SPF-PTR | SPF verwendet den veralteten Mechanismus «ptr» | niedrig |
| E-Mail | SPF-SOFTFAIL | SPF nur «weich» (~all) | niedrig |
| E-Mail | AEHNLICH-OHNE-MAIL | Ähnliche Domain registriert, derzeit ohne E-Mail | info |
| E-Mail | TLSRPT-FEHLT | Keine TLS-RPT-Berichte konfiguriert | info |
| DNS | DNSSEC-KAPUTT | DNSSEC fehlerhaft (DS ohne DNSKEY) | hoch |
| DNS | NS-KEINE | Keine Nameserver gefunden | hoch |
| DNS | SUB-UEBERNEHMBAR | Subdomain zeigt auf gekündigten Dienst (Subdomain-Takeover möglich) | hoch |
| DNS | NS-NUR-EINER | Nur ein Nameserver | mittel |
| DNS | SUB-DIENST-FREI | Subdomain zeigt Fehlerseite eines Cloud-Dienstes (möglicherweise übernehmbar) | mittel |
| DNS | CAA-FEHLT | Kein CAA-Eintrag vorhanden | niedrig |
| DNS | DNSSEC-AUS | DNSSEC nicht aktiviert | niedrig |
| DNS | DNSSEC-OHNE-DS | DNSSEC halb eingerichtet (DNSKEY ohne DS) | niedrig |
| DNS | SUB-VERWAIST | Subdomain zeigt auf ein nicht mehr existierendes Ziel | niedrig |
| Web | WEB-ZERT-ABGELAUFEN | TLS-Zertifikat abgelaufen | hoch |
| Web | WEB-ZERT-UNGUELTIG | TLS-Zertifikat ungültig | hoch |
| Web | WEB-KEINE-HTTPS-WEITERLEITUNG | Keine Weiterleitung von HTTP auf HTTPS | mittel |
| Web | WEB-NICHT-ERREICHBAR | Webseite per HTTPS nicht erreichbar | mittel |
| Web | WEB-TLS-ALT | Veraltete TLS-Versionen 1.0/1.1 aktiviert | mittel |
| Web | WEB-COOKIES-UNSICHER | Cookies ohne empfohlene Schutzattribute | niedrig |
| Web | WEB-HEADER-FEHLEN | Empfohlene Sicherheits-Header fehlen | niedrig |
| Web | WEB-HSTS-FEHLT | HTTP Strict Transport Security (HSTS) fehlt oder ist zu kurz | niedrig |
| Web | WEB-ZERT-LAEUFT-AB | TLS-Zertifikat läuft bald ab | niedrig |
| Web | WEB-CMS-VERSION | Webseite verrät CMS und Version | info |
| Web | WEB-SECURITYTXT-FEHLT | Keine security.txt veröffentlicht | info |
| Web | WEB-VERSION-SICHTBAR | Webserver verrät seine Software-Version | info |
| Netzwerk | SHODAN-DATENBANK | Datenbank oder Server-Schnittstelle aus dem Internet erreichbar | kritisch |
| Netzwerk | SHODAN-FERNZUGRIFF | Fernzugriff direkt aus dem Internet erreichbar (z. B. RDP) | kritisch |
| Netzwerk | SHODAN-KEV-RANSOMWARE | Sicherheitslücke, die von Ransomware-Gruppen ausgenutzt wird (CISA KEV) | kritisch |
| Netzwerk | SHODAN-STEUERUNG | Industrie- oder Gebäudesteuerung aus dem Internet erreichbar | kritisch |
| Netzwerk | SHODAN-KEV | Aktiv ausgenutzte Sicherheitslücke (CISA KEV) | hoch |
| Netzwerk | SHODAN-CVE | Bekannte Sicherheitslücke laut Versionsangabe | mittel |
| Netzwerk | SHODAN-UNSICHER | Unverschlüsselte oder heikle Verwaltungsdienste aus dem Internet erreichbar | mittel |

Die Befunde der Kategorie **Netzwerk** beruhen auf öffentlichen Daten (Shodan InternetDB, CISA KEV).
Die `nmap`-Befehle unter `pruefen` nur mit Einverständnis des Inhabers ausführen.

## Werkzeuge

```bash
pip install pyyaml pytest
python werkzeuge/katalog.py pruefen                              # Format prüfen
python werkzeuge/katalog.py markdown --domain muster-ag.ch > b.md  # als Markdown
python werkzeuge/katalog.py markdown --sz                         # Schreibweise Deutschland
python werkzeuge/katalog.py sysreptor > vorlagen.json             # SysReptor-Vorlagen
cat vorlagen.json | reptor template                                # in SysReptor hochladen
pytest
```

## Mitmachen

Neue Befunde und Korrekturen gerne als Pull Request. Bitte nur eigene Texte oder Texte
mit kompatibler Lizenz. Vor dem Pull Request `python werkzeuge/katalog.py pruefen` und
`pytest` ausführen – der Prüfer findet u. a. fehlende Felder, falsche IDs und durch
Zeilenumbrüche getrennte Wörter.

## Über

Entwickelt von Juan Amorós García – [Limmattal IT & Security](https://limmattal-it.ch).
Fragen und Ideen: als Issue oder an kontakt@limmattal-it.ch.
Die Befunde werden in [pruefstand](https://github.com/chilaba8/pruefstand) verwendet,
einem passiven E-Mail- und DNS-Sicherheits-Check für KMU.

## Lizenz

Texte: CC BY 4.0 · Code: MIT – siehe [LICENSE](LICENSE). Ohne Gewähr.
