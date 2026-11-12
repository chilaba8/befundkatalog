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

| ID | Titel | Schweregrad |
|---|---|---|
| SPF-FEHLT | Kein SPF-Eintrag vorhanden | hoch |
| SPF-ALL-OFFEN | SPF erlaubt allen Servern den Versand | kritisch |
| DMARC-FEHLT | Kein DMARC-Eintrag vorhanden | hoch |
| DMARC-P-NONE | DMARC nur im Beobachtungsmodus | hoch |
| DKIM-NICHT-GEFUNDEN | Kein DKIM-Schlüssel unter gängigen Selektoren gefunden | mittel |

## Werkzeuge

```bash
pip install pyyaml pytest
python werkzeuge/katalog.py pruefen                              # Format prüfen
python werkzeuge/katalog.py markdown --domain muster-ag.ch > b.md  # als Markdown
python werkzeuge/katalog.py markdown --sz                         # Schreibweise Deutschland
pytest
```

## Mitmachen

Neue Befunde und Korrekturen gerne als Pull Request. Bitte nur eigene Texte oder Texte
mit kompatibler Lizenz.

## Lizenz

Texte: CC BY 4.0 · Code: MIT – siehe [LICENSE](LICENSE).
