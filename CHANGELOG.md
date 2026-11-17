# Änderungen

## Unveröffentlicht

- 2 neue Befunde (Entwurf) – jetzt 47: CAA-FEHLT (DNS) und AEHNLICH-OHNE-MAIL (E-Mail),
  beide von pruefstand gemeldet, bisher ohne Text im Katalog.

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
