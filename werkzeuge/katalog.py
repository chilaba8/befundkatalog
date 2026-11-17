"""befundkatalog – Befunde prüfen und exportieren.

    python werkzeuge/katalog.py pruefen
    python werkzeuge/katalog.py markdown [--domain beispiel.ch] [--sz] > befunde.md
    python werkzeuge/katalog.py sysreptor > vorlagen.json   # dann: cat vorlagen.json | reptor template
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

import yaml

WURZEL = Path(__file__).resolve().parent.parent / "befunde"
PFLICHT = ["id", "version", "status", "kategorie", "schweregrad", "titel", "geschaeftsleitung",
           "beschreibung", "auswirkung", "empfehlung", "pruefen", "referenzen"]
SCHWEREGRADE = ["kritisch", "hoch", "mittel", "niedrig", "info"]
STATUS = ["entwurf", "geprueft"]
GETRENNT = re.compile(r"\w- (?!(?:und|oder|bzw\.|sowie|als) )\w+")

# «pruefen» wird von Lesern ins Terminal kopiert. Ein Beitrag darf dort nichts Gefährliches
# unterbringen: nur lesende Werkzeuge, nur «|» und «&&», keine Dateien schreiben.
BEFEHLE = {"dig", "curl", "openssl", "nmap", "whois", "grep", "head", "echo"}
CURL_OPTIONEN = {"-s", "-I", "-sI", "-L", "-sL", "-sIL"}
OPENSSL_UNTERBEFEHLE = {"s_client", "x509"}
PLATZHALTER = re.compile(r"<[a-z][a-z-]*>")


def pruefe_befehl(befehl: str) -> str | None:
    """None, wenn der Prüfbefehl harmlos ist; sonst der Grund."""
    if re.fullmatch(r"https://[^\s`$;|&<>'\"]+", PLATZHALTER.sub("x", befehl)):
        return None                                   # nur ein Link zum Nachschauen
    if any(z in befehl for z in ("`", "$(", "${", "\n")):
        return "Befehlsersetzung oder Zeilenumbruch"
    if "nmap" in befehl and "Einverständnis" not in befehl:
        return "nmap nur mit Hinweis «# nur mit Einverständnis des Inhabers»"
    try:
        lex = shlex.shlex(PLATZHALTER.sub("PLATZHALTER", befehl), posix=True, punctuation_chars=True)
        token = list(lex)                             # «# …» am Ende wird als Kommentar entfernt
    except ValueError as e:
        return f"nicht lesbar ({e})"
    teile, aktuell, i = [], [], 0
    while i < len(token):
        t = token[i]
        if t in ("|", "&&"):
            teile.append(aktuell)
            aktuell = []
        elif t == "<" and token[i + 1:i + 2] == ["/dev/null"]:
            i += 1
        elif t == ">" and aktuell[-1:] == ["2"] and token[i + 1:i + 2] == ["/dev/null"]:
            aktuell.pop()
            i += 1
        elif t and set(t) <= set("();<>|&"):
            return f"Operator «{t}» nicht erlaubt (nur | und &&)"
        else:
            aktuell.append(t)
        i += 1
    teile.append(aktuell)
    for teil in teile:
        if not teil:
            return "leerer Befehl"
        prog, args = teil[0], teil[1:]
        if prog not in BEFEHLE:
            return f"Programm «{prog}» nicht erlaubt ({', '.join(sorted(BEFEHLE))})"
        if prog == "curl" and (bad := [a for a in args if a.startswith("-") and a not in CURL_OPTIONEN]):
            return f"curl-Option {bad[0]} nicht erlaubt (nur {', '.join(sorted(CURL_OPTIONEN))})"
        if prog == "openssl" and (not args or args[0] not in OPENSSL_UNTERBEFEHLE
                                  or any(a in ("-out", "-writerand", "-keylogfile", "-sess_out") for a in args)):
            return "openssl nur s_client/x509, ohne Dateien zu schreiben"
        if prog == "nmap" and any(a.startswith(("--script", "-sC", "-o", "-iL", "--resume")) for a in args):
            return "nmap ohne Skripte und ohne Ausgabedateien"
        if prog == "echo" and args:
            return "echo nur ohne Argumente (für «echo | openssl …»)"
    return None
SPRACHEN_TITEL = ["de", "en", "es"]
ID_MUSTER = re.compile(r"^[A-Z0-9]+(-[A-Z0-9]+)+$")
# Für de-DE: nur bekannte Wörter (wie in pruefstand/sprache.py)
SS_ZU_SZ = {"grosse": "große", "gross": "groß", "Massnahme": "Maßnahme", "Massnahmen": "Maßnahmen",
            "ausserdem": "außerdem", "Ausserdem": "Außerdem",
            "regelmässig": "regelmäßig", "regelmässige": "regelmäßige", "liessen": "ließen",
            "Mindestmass": "Mindestmaß", "weiss": "weiß", "heisst": "heißt", "Strasse": "Straße"}


def lade_alle(wurzel: Path = WURZEL) -> list[tuple[Path, dict]]:
    return [(p, yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(wurzel.rglob("*.yaml"))]


def pruefe_befund(pfad: Path, b: dict) -> list[str]:
    fehler = []
    if not isinstance(b, dict):
        return [f"{pfad.name}: kein YAML-Objekt"]
    for feld in PFLICHT:
        if not b.get(feld):
            fehler.append(f"{pfad.name}: Feld «{feld}» fehlt oder ist leer")
    if b.get("id") and not ID_MUSTER.match(b["id"]):
        fehler.append(f"{pfad.name}: ungültige id «{b['id']}» (GROSS-MIT-BINDESTRICH)")
    if b.get("id") and pfad.stem != b["id"]:
        fehler.append(f"{pfad.name}: Dateiname muss «{b['id']}.yaml» sein")
    if b.get("schweregrad") not in SCHWEREGRADE:
        fehler.append(f"{pfad.name}: schweregrad muss einer von {SCHWEREGRADE} sein")
    if b.get("status") not in STATUS:
        fehler.append(f"{pfad.name}: status muss einer von {STATUS} sein")
    titel = b.get("titel") or {}
    for s in SPRACHEN_TITEL:
        if not isinstance(titel, dict) or not titel.get(s):
            fehler.append(f"{pfad.name}: titel.{s} fehlt")
    if b.get("cwe") and not re.match(r"^CWE-\d+$", str(b["cwe"])):
        fehler.append(f"{pfad.name}: cwe muss die Form CWE-123 haben")
    # YAML «>-» macht aus einem Zeilenumbruch ein Leerzeichen: «DNS-⏎Antworten» wird «DNS- Antworten».
    # Erlaubt bleiben Ergänzungsstriche wie «Rechnungs- und CEO-Betrug».
    for feld in ("geschaeftsleitung", "beschreibung", "auswirkung", "empfehlung"):
        m = GETRENNT.search(str(b.get(feld) or ""))
        if m:
            fehler.append(f"{pfad.name}: {feld}: getrenntes Wort «{m.group(0)}» (Zeilenumbruch nach Bindestrich)")
    if b.get("pruefen") and (grund := pruefe_befehl(str(b["pruefen"]))):
        fehler.append(f"{pfad.name}: pruefen: {grund}")
    if "ß" in yaml.safe_dump(b, allow_unicode=True):
        fehler.append(f"{pfad.name}: Texte in Schweizer Schreibweise (ss statt ß); de-DE entsteht beim Export")
    return fehler


def fuer_deutschland(text: str) -> str:
    for ch, de in SS_ZU_SZ.items():
        text = re.sub(rf"(?<![\w.@/-]){ch}(?![\w@/-])(?!\.\w)", de, text)
    return re.sub(r"«([^«»\n]*)»", r"„\1“", text)


def als_markdown(befunde: list[dict], domain: str, sz: bool) -> str:
    teile = []
    for b in befunde:
        def t(text: str) -> str:
            text = str(text).replace("{domain}", domain)
            return fuer_deutschland(text) if sz else text
        teile.append(
            f"## {t(b['titel']['de'])}\n\n"
            f"**ID:** `{b['id']}` · **Schweregrad:** {b['schweregrad']} · **CWE:** {b.get('cwe', '–')}\n\n"
            f"**Für die Geschäftsleitung:** {t(b['geschaeftsleitung'])}\n\n"
            f"### Beschreibung\n{t(b['beschreibung'])}\n\n"
            f"### Auswirkung\n{t(b['auswirkung'])}\n\n"
            f"### Empfehlung\n{t(b['empfehlung'])}\n\n"
            f"### So prüfen Sie die Behebung\n```\n{t(b['pruefen'])}\n```\n\n"
            "### Referenzen\n" + "".join(f"- {r}\n" for r in b["referenzen"]))
    return "\n---\n\n".join(teile)


# Format laut https://docs.sysreptor.com/cli/projects-and-templates/template (geprüft 12.11.2026):
# {"tags": [...], "translations": [{"language", "is_main", "status", "data": {...}}]}
SYSREPTOR_STATUS = {"entwurf": "in-progress", "geprueft": "finished"}


def als_sysreptor(befunde: list[dict]) -> list[dict]:
    """Finding-Templates für SysReptor. Felder wie im SysReptor-Standarddesign; Sprache de-DE
    (deshalb mit ß). Der Platzhalter {domain} bleibt als Text stehen."""
    vorlagen = []
    for b in befunde:
        def t(text: str) -> str:
            return fuer_deutschland(str(text).replace("{domain}", "<domain>"))
        tags = [b["kategorie"].lower(), b["schweregrad"], b["id"].lower()]
        if b.get("cwe"):
            tags.append(b["cwe"].lower())
        vorlagen.append({
            "tags": tags,
            "translations": [{
                "language": "de-DE",
                "is_main": True,
                "status": SYSREPTOR_STATUS[b["status"]],
                "data": {
                    "title": t(b["titel"]["de"]),
                    "summary": t(b["geschaeftsleitung"]),
                    "description": t(b["beschreibung"]),
                    "impact": t(b["auswirkung"]),
                    "recommendation": t(b["empfehlung"]) + "\n\n**So prüfen Sie die Behebung:**\n\n```\n"
                                      + t(b["pruefen"]) + "\n```",
                    "references": [str(r) for r in b["referenzen"]],
                },
            }],
        })
    return vorlagen


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="katalog")
    sub = p.add_subparsers(dest="befehl", required=True)
    sub.add_parser("pruefen", help="alle Befunde auf Pflichtfelder und Format prüfen")
    md = sub.add_parser("markdown", help="alle Befunde als Markdown ausgeben")
    md.add_argument("--domain", default="<domain>")
    md.add_argument("--sz", action="store_true", help="Schreibweise für Deutschland (ß, „…“)")
    sub.add_parser("sysreptor", help="alle Befunde als SysReptor-Finding-Templates (JSON)")
    args = p.parse_args(argv)

    alle = lade_alle()
    if args.befehl == "pruefen":
        fehler = [f for pfad, b in alle for f in pruefe_befund(pfad, b)]
        ids = [b.get("id") for _, b in alle]
        fehler += [f"id doppelt: {i}" for i in set(ids) if ids.count(i) > 1]
        for f in fehler:
            print(f, file=sys.stderr)
        print(f"{len(alle)} Befunde geprüft, {len(fehler)} Fehler.")
        return 1 if fehler else 0
    if args.befehl == "sysreptor":
        print(json.dumps(als_sysreptor([b for _, b in alle]), ensure_ascii=False, indent=2))
        return 0
    print(als_markdown([b for _, b in alle], args.domain, args.sz))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
