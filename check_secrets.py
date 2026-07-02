"""
check_secrets.py — Kontrola, že vo webových súboroch (pred nasadením na server)
nie sú omylom zacommitnuté API kľúče, IBAN alebo heslá (Fáza 7.3).

Spustenie: py -3 check_secrets.py
"""
import os
import re
import sys

_ZAKAZANE_VZORY = [
    (re.compile(r"gsk_[a-zA-Z0-9]{20,}"), "Groq API kľúč"),
    (re.compile(r"sk-[a-zA-Z0-9]{30,}"), "API kľúč (OpenAI-style)"),
    (re.compile(r"IBAN[:\s]+SK\d{20,}", re.IGNORECASE), "IBAN"),
    (re.compile(r"password\s*[:=]\s*['\"]?\S{6,}", re.IGNORECASE), "heslo"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
]

_PRIPONY = (".html", ".htm", ".js", ".css", ".json", ".md", ".txt", ".py")
_VYNECHAT_PRIECINKY = {".git", "__pycache__", ".venv", "node_modules"}


def over_ze_nie_su_secrets_vo_web_subore(root: str | None = None) -> list[str]:
    root = root or os.path.dirname(os.path.abspath(__file__))
    najdene: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _VYNECHAT_PRIECINKY]
        for meno in filenames:
            if not meno.endswith(_PRIPONY):
                continue
            if meno == os.path.basename(__file__):
                continue  # vlastné vzory by sa inak našli samé v sebe
            cesta = os.path.join(dirpath, meno)
            try:
                obsah = open(cesta, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for vzor, popis in _ZAKAZANE_VZORY:
                zhoda = vzor.search(obsah)
                if zhoda:
                    najdene.append(f"KRITICKÉ: {os.path.relpath(cesta, root)} obsahuje {popis} ({zhoda.group()[:20]}...)")
    return najdene


if __name__ == "__main__":
    problemy = over_ze_nie_su_secrets_vo_web_subore()
    if problemy:
        print("NÁJDENÉ PROBLÉMY:")
        for p in problemy:
            print(f"  {p}")
        sys.exit(1)
    print("OK — žiadne secrets nájdené vo web súboroch.")
    sys.exit(0)
