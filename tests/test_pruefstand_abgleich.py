"""Abgleich mit pruefstand: Jeder Hinweis, jede Warnung und jeder kritische Befund der
Domain-Prüfung muss im Katalog einen Text haben – und jeder Befund im Katalog muss in
pruefstand noch vorkommen.

pruefstand wird nicht importiert, sondern sein Quelltext gelesen (ast). Gesucht wird:
  1. Umgebungsvariable PRUEFSTAND_SRC (Pfad zum Paket «pruefstand», so in der CI),
  2. sonst ../pruefstand/src/pruefstand neben diesem Repository.
Ohne pruefstand wird der Test übersprungen – ausser PRUEFSTAND_SRC ist gesetzt.
"""

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "werkzeuge"))
import katalog  # noqa: E402

RELEVANT = {"KRITISCH", "WARNUNG", "HINWEIS"}

# Befunde der Domain-Prüfung, die bewusst keinen Katalogtext haben.
AUSNAHMEN = {
    "*-DNS-FEHLER": "Prüfung nicht möglich (DNS-Fehler), kein Befund über die Domain",
    "DNSSEC-FEHLER": "DNSSEC nicht prüfbar (DNS-Fehler), kein Befund über die Domain",
    "WEB-HTTPS-FEHLER": "Startseite nicht ladbar (Netzfehler), kein Befund über die Domain",
}


def _pruefstand_pfad() -> Path | None:
    if env := os.environ.get("PRUEFSTAND_SRC"):
        pfad = Path(env)
        assert (pfad / "pruefungen").is_dir(), f"PRUEFSTAND_SRC zeigt nicht auf pruefstand: {pfad}"
        return pfad
    pfad = Path(__file__).resolve().parents[2] / "pruefstand" / "src" / "pruefstand"
    return pfad if (pfad / "pruefungen").is_dir() else None


def _ids(knoten: ast.expr) -> list[str]:
    """IDs aus dem ersten Argument: "X", "A" if … else "B", f"{name}-DNS-FEHLER" → "*-DNS-FEHLER"."""
    if isinstance(knoten, ast.Constant) and isinstance(knoten.value, str):
        return [knoten.value]
    if isinstance(knoten, ast.IfExp):
        return _ids(knoten.body) + _ids(knoten.orelse)
    if isinstance(knoten, ast.JoinedStr):
        return ["".join(t.value if isinstance(t, ast.Constant) else "*" for t in knoten.values)]
    return []


def pruefstand_befunde(pfad: Path) -> dict[str, set[str]]:
    """{ID: {Status, …}} aller Befund(…)- und neu(…)-Aufrufe der Domain-Prüfung."""
    dateien = sorted((pfad / "pruefungen").glob("*.py")) + [pfad / "pruefung.py"]
    befunde: dict[str, set[str]] = {}
    for datei in dateien:
        for k in ast.walk(ast.parse(datei.read_text(encoding="utf-8"))):
            if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                    and k.func.id in ("Befund", "neu") and k.args):
                continue
            status = {a.attr for arg in [*k.args[1:], *(kw.value for kw in k.keywords)]
                      for a in ast.walk(arg)
                      if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name)
                      and a.value.id == "Status"}
            for bid in _ids(k.args[0]):
                befunde.setdefault(bid, set()).update(status)
    return befunde


@pytest.fixture(scope="module")
def befunde():
    pfad = _pruefstand_pfad()
    if pfad is None:
        pytest.skip("pruefstand nicht gefunden (PRUEFSTAND_SRC setzen oder daneben auschecken)")
    return pruefstand_befunde(pfad)


@pytest.fixture(scope="module")
def katalog_ids():
    return {b["id"] for _, b in katalog.lade_alle()}


def test_parser_findet_befunde(befunde):
    # Schützt davor, dass der Abgleich stillschweigend nichts findet.
    assert len(befunde) > 50
    assert befunde["SHODAN-KEV"] == {"KRITISCH"}
    assert {"MTASTS-TESTING", "MTASTS-NONE", "*-DNS-FEHLER"} <= set(befunde)


def test_jeder_befund_von_pruefstand_hat_text(befunde, katalog_ids):
    fehlt = sorted(bid for bid, st in befunde.items()
                   if st & RELEVANT and bid not in katalog_ids and bid not in AUSNAHMEN)
    assert not fehlt, ("pruefstand meldet Befunde ohne Text im Katalog: " + ", ".join(fehlt)
                       + " – YAML anlegen oder in AUSNAHMEN begründen.")


def test_katalog_ohne_verwaiste_befunde(befunde, katalog_ids):
    verwaist = sorted(katalog_ids - set(befunde))
    assert not verwaist, "Im Katalog, aber nicht (mehr) in pruefstand: " + ", ".join(verwaist)


def test_ausnahmen_aktuell(befunde, katalog_ids):
    veraltet = sorted(a for a in AUSNAHMEN if a not in befunde or a in katalog_ids)
    assert not veraltet, "AUSNAHMEN nicht mehr nötig: " + ", ".join(veraltet)
