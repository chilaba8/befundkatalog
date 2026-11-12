# befundkatalog

**Pentest- und Audit-Befunde auf Deutsch – frei verwendbar.**

Wer Sicherheitsberichte für Kunden in der Schweiz, Deutschland oder Österreich schreibt,
formuliert dieselben Befunde immer wieder neu. Öffentliche Sammlungen gibt es fast nur
auf Englisch. `befundkatalog` sammelt Befunde in verständlichem Deutsch: technisch für
den Informatiker und in einem Satz für die Geschäftsleitung.

> Status: Anfang. Die Texte sind **Entwürfe** und brauchen eine Prüfung durch
> Muttersprachler (`status: entwurf`). Korrekturen sind sehr willkommen.

## Aufbau eines Befunds

Eine YAML-Datei pro Befund, z. B. [`befunde/email/DMARC-FEHLT.yaml`](befunde/email/DMARC-FEHLT.yaml):

| Feld | Inhalt |
|---|---|
| `id` | stabiler Schlüssel – identisch mit den IDs von [pruefstand](https://github.com/chilaba8/pruefstand) |
| `schweregrad` | kritisch · hoch · mittel · niedrig · info |
| `cwe` | passende CWE-Nummer |
| `titel` | Deutsch, Englisch, Spanisch |
| `geschaeftsleitung` | ein bis zwei Sätze ohne Fachbegriffe |
| `beschreibung`, `auswirkung`, `empfehlung` | technischer Text; `{domain}` wird beim Export ersetzt |
| `pruefen` | Befehl, mit dem man die Behebung prüft |
| `referenzen` | RFC, Normen, offizielle Doku |

Texte sind in **Schweizer Schreibweise** (ss, «…»). Für Deutschland erzeugt der Export
ß und „…“ (`--sz`).

## Befunde

| Kategorie | ID | Titel | Schweregrad |
|---|---|---|---|
| DNS | DNSSEC-AUS | DNSSEC nicht aktiviert | niedrig |
| DNS | SUB-UEBERNEHMBAR | Subdomain zeigt auf gekündigten Dienst (Subdomain-Takeover möglich) | hoch |
| E-Mail | AEHNLICH-MIT-MAIL | Ähnliche Domain mit E-Mail-Empfang registriert | mittel |
| E-Mail | DKIM-NICHT-GEFUNDEN | Kein DKIM-Schlüssel unter gängigen Selektoren gefunden | mittel |
| E-Mail | DMARC-FEHLT | Kein DMARC-Eintrag vorhanden | hoch |
| E-Mail | DMARC-KEIN-RUA | Keine DMARC-Berichte (rua) konfiguriert | niedrig |
| E-Mail | DMARC-P-NONE | DMARC nur im Beobachtungsmodus (p=none) | hoch |
| E-Mail | MTASTS-FEHLT | Keine MTA-STS-Richtlinie für eingehende E-Mails | niedrig |
| E-Mail | SPF-ALL-OFFEN | SPF erlaubt allen Servern den Versand (+all / ?all) | kritisch |
| E-Mail | SPF-FEHLT | Kein SPF-Eintrag vorhanden | hoch |
| Web | WEB-HSTS-FEHLT | HTTP Strict Transport Security (HSTS) fehlt oder ist zu kurz | niedrig |
| Web | WEB-SECURITYTXT-FEHLT | Keine security.txt veröffentlicht | info |
| Web | WEB-TLS-ALT | Veraltete TLS-Versionen 1.0/1.1 aktiviert | mittel |

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
mit kompatibler Lizenz.

## Lizenz

Texte: CC BY 4.0 · Code: MIT – siehe [LICENSE](LICENSE).
