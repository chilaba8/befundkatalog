import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "werkzeuge"))
import katalog  # noqa: E402


def test_alle_befunde_gueltig():
    alle = katalog.lade_alle()
    assert alle, "keine Befunde gefunden"
    fehler = [f for pfad, b in alle for f in katalog.pruefe_befund(pfad, b)]
    assert fehler == []


def test_ids_eindeutig():
    ids = [b["id"] for _, b in katalog.lade_alle()]
    assert len(ids) == len(set(ids))


def test_validator_findet_fehler(tmp_path):
    p = tmp_path / "FALSCH.yaml"
    fehler = katalog.pruefe_befund(p, {"id": "klein", "schweregrad": "egal", "titel": {"de": "x"}})
    text = "\n".join(fehler)
    assert "ungültige id" in text and "schweregrad" in text and "titel.en" in text and "Dateiname" in text


def test_markdown_und_deutschland():
    md = katalog.als_markdown([b for _, b in katalog.lade_alle()], "muster-ag.ch", sz=True)
    assert "muster-ag.ch" in md and "{domain}" not in md
    assert "Maßnahme" in md and "«" not in md


def test_sysreptor_format():
    vorlagen = katalog.als_sysreptor([b for _, b in katalog.lade_alle()])
    v = vorlagen[0]
    assert set(v) == {"tags", "translations"}
    tr = v["translations"][0]
    assert tr["language"] == "de-DE" and tr["is_main"] is True and tr["status"] in ("in-progress", "finished")
    assert {"title", "summary", "description", "impact", "recommendation", "references"} <= set(tr["data"])
    assert all("{domain}" not in str(x["translations"][0]["data"]) for x in vorlagen)
