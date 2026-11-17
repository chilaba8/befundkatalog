# Änderungen

## Unveröffentlicht

- Prüfbefehle (`pruefen`) werden automatisch geprüft, weil Leser sie ins Terminal kopieren:
  nur dig, curl, openssl, nmap, whois, grep, head, echo; nur `|` und `&&`; curl ohne
  Ausgabedateien oder Uploads, nmap ohne Skripte und nur mit Hinweis auf das Einverständnis.

## 0.3.0 – 2026-11-17

- 14 neue Befunde – jetzt 59, für alle Hinweise der Domain-Prüfung von pruefstand:
  CAA-FEHLT, AEHNLICH-OHNE-MAIL, SPF-SOFTFAIL, SPF-PTR, TLSRPT-FEHLT, MTASTS-TESTING,
  MTASTS-NONE, CLOUD-M365-NICHT-IM-SPF, DNSSEC-OHNE-DS, WEB-HEADER-FEHLEN,
  WEB-COOKIES-UNSICHER, WEB-CMS-VERSION, WEB-VERSION-SICHTBAR, SHODAN-CVE.
- Alle neuen Befunde geprüft (`status: geprueft`).

## 0.2.0 – 2026-11-17

- 32 neue Befunde – jetzt 45, für alle Warnungen und kritischen Befunde von pruefstand:
  SPF (Fehler, ohne «all», zu viele DNS-Abfragen), DMARC (mehrfach, ungültig, pct, sp=none),
  DKIM (zu kurz, widerrufen), ähnliche Domains (neu registriert, eigene ungeschützt/abgelaufen),
  MX, MTA-STS, Sperrlisten, Nameserver, DNSSEC fehlerhaft, verwaiste Subdomains,
  Zertifikate, HTTPS sowie neue Kategorie **Netzwerk** (offene Dienste, CISA KEV).
- Alle Befunde sprachlich und fachlich geprüft (`status: geprueft`).
- DMARC-FEHLT: genauer, wann DMARC scheitert (weder SPF noch DKIM mit passender Domain).
- AEHNLICH-MIT-MAIL: Text für die Geschäftsleitung korrigiert (MX = E-Mail-Empfang).
- Durch Zeilenumbrüche getrennte Wörter behoben («DNS-Antworten», «TLS-RPT-Berichten»);
  der Prüfer erkennt solche Fehler jetzt automatisch.
- Export für Deutschland (`--sz`): auch «Ausserdem», «regelmässig», «liessen» und «Mindestmass».

## 0.1.0 – 2026-11-12

- 13 Befunde (E-Mail, DNS, Web) mit Titeln auf Deutsch, Englisch und Spanisch.
- Werkzeug `katalog.py`: prüfen, Markdown-Export, SysReptor-Vorlagen.
