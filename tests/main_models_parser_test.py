#!/usr/bin/env python3
"""Parser/Writer-Unit-Test für Hauptmodell/Provider (v0.0.241).

Deckt den Befund vom 30.08.2026 ab: Diese config.yaml-Zeile

    memory:
      provider: holographic

ließ das Atlas-Hauptmodell-Feld „holographic" anzeigen, weil _parse_config_main
eingerückte Zeilen wie Top-Level-Keys las (letzter Treffer gewann). Fix: Nur
Top-Level-Zeilen zählen; model/provider kommen aus dem top-level 'model:'-Block
(eingerückt provider/default). Der Writer schreibt in DIESEN Block statt
top-level Flach-Strings (die den Block zerstörten — config.yaml.corrupt-Falle).

Läuft ohne Server und ohne pyyaml (Roundtrip + Text-Asserts).
Aufruf:  venv/bin/python tests/main_models_parser_test.py
Exit 0 = alles grün. Ausgabe endet mit "ALLE BESTANDEN".
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ATLAS_DB auf Wegwerf-DB, damit der Import von app.main nichts anfasst
os.environ.setdefault("ATLAS_DB", "/tmp/atlas_parser_test.db")

from app.main import _parse_config_main, _write_hermes_main, _write_hermes_aux  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print(("  OK  " if cond else "FEHLT ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


ML = 'model:\n  provider: custom:kraemer-it\n  default: DeepSeek-V4-Flash\n  max_tokens: 32768\n'
MEM = 'memory:\n  provider: holographic\n'
AUX = ('auxiliary:\n  vision: {provider: auto, model: \'\'}\n'
       '  web_extract: {provider: auto, model: \'\'}\n')
CP = ('custom_providers:\n  - base_url: https://x.example/v1\n'
      '    model: DeepSeek-V4-Flash\n    models:\n      - Qwen3\n      - DeepSeek-V4-Flash\n')

BASE = ML + MEM + AUX + CP + 'reasoning_effort: medium\n'


def parse(txt):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(txt)
        p = f.name
    try:
        return _parse_config_main(p)
    finally:
        os.unlink(p)


def write(txt, main):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(txt)
        p = f.name
    try:
        os.environ["ATLAS_HERMES_CONFIG_PATH"] = p
        try:
            _write_hermes_main(main, "test")
        finally:
            del os.environ["ATLAS_HERMES_CONFIG_PATH"]
    finally:
        txt_out = open(p).read() if os.path.exists(p) else ""
        os.unlink(p)
    return txt_out


print("=== Parser ===")
main, aux = parse(BASE)
check("provider aus model:-Block (nicht memory.holographic)",
      main["provider"] == "custom:kraemer-it", main["provider"])
check("model = model.default", main["model"] == "DeepSeek-V4-Flash", main["model"])
check("reasoning_effort top-level", main["reasoning_effort"] == "medium")
check("fast_mode leer", main["fast_mode"] == "")

# Flach-Altform (top-level String) bleibt lesbar
main2, _ = parse('model: "Qwen3"\nprovider: "custom:alt"\nmemory:\n  provider: holographic\n')
check("Altform top-level String lesbar", main2["model"] == "Qwen3" and main2["provider"] == "custom:alt")

# Nur memory.provider vorhanden -> Hauptmodell leer (kein holographic-Leak)
main3, _ = parse("memory:\n  provider: holographic\n")
check("nur memory: -> Hauptmodell leer", main3["provider"] == "" and main3["model"] == "")

# eingerückte provider/model unter custom_providers zählen NICHT
main4, _ = parse("custom_providers:\n  - provider: x\n    model: y\n")
check("custom_providers-Zeilen zählen nicht",
      main4["provider"] == "" and main4["model"] == "")

print("=== Writer ===")
out = write(BASE, {"provider": "custom:test-prov", "model": "Qwen3"})
check("Block-Kinder geschrieben",
      '  provider: "custom:test-prov"' in out and '  default: "Qwen3"' in out)
check("keine Flach-Form model:/provider: top-level",
      not any(re.match(r'^(model|provider):\s*\S', ln) for ln in out.splitlines()
              if ln.strip() and not ln[:1].isspace()))
check("memory.provider unangetastet", "provider: holographic" in out)
check("nur EIN model:-Header",
      len([ln for ln in out.splitlines() if re.match(r'^model:', ln)]) == 1)
roundtrip, _ = parse(out)
check("Roundtrip: Parser liest Geschriebenes",
      roundtrip["provider"] == "custom:test-prov" and roundtrip["model"] == "Qwen3")

# Reasoning-only: Block bleibt vollständig
out2 = write(BASE.replace('reasoning_effort: medium\n', ''), {"reasoning_effort": "high"})
check("Reasoning-only: Block bleibt", 'default: DeepSeek-V4-Flash' in out2
      and 'reasoning_effort: "high"' in out2 and "provider: holographic" in out2)

# Reset: provider/default aus dem Block entfernt, max_tokens (fremdes Kind) BLEIBT.
# v0.0.242: Der Block wird nur entfernt, wenn er danach kinderlos wäre.
out3 = write(BASE, {"provider": "", "model": ""})
blk3 = re.search(r'^model:.*?(?=^[^\s#]|\Z)', out3, re.M | re.S)
blk3txt = blk3.group(0) if blk3 else ""
check("Reset: kein model:-Block mehr" if not blk3 else
      "Reset: provider/default entfernt, max_tokens bleibt",
      (not blk3) or (
          "provider: holographic" in out3 and
          "  provider:" not in blk3txt and
          "  default:" not in blk3txt and
          "max_tokens: 32768" in blk3txt
      ))

# Korrupte Altform heilen (Waisen unter top-level model:String)
kaputt = 'model: "DeepSeek-V4-Flash"\n  provider: custom:alt\n  default: Alt\nmemory:\n  provider: holographic\n'
out4 = write(kaputt, {"provider": "custom:neu", "model": "Neu"})
check("korrupte Altform geheilt",
      '  provider: "custom:neu"' in out4 and '  default: "Neu"' in out4
      and not any(re.match(r'^model:\s*\S', ln) for ln in out4.splitlines())
      and 'provider: holographic' in out4)

# Kein model:-Key -> Block wird angelegt
out5 = write("timezone: Europe/Berlin\n", {"provider": "custom:x", "model": "Y"})
rt5, _ = parse(out5)
check("Block anlegen ohne Vorhandensein",
      rt5["provider"] == "custom:x" and rt5["model"] == "Y" and "timezone: Europe/Berlin" in out5)

# reasoning/fast fehlen in config -> werden angelegt
out6 = write("timezone: Europe/Berlin\n", {"reasoning_effort": "low", "fast_mode": "fast"})
check("reasoning/fast anlegen", 'reasoning_effort: "low"' in out6 and 'fast_mode: "fast"' in out6)

# E2E 22g-Simulation (VORLAGE wie run_e2e_local.py: model-Block direkt vor auxiliary:)
v22g = ('model:\n  provider: custom:kraemer-it\n  default: DeepSeek-V4-Flash\n'
        '  max_tokens: 32768\nmemory:\n  provider: holographic\n'
        'auxiliary:\n  vision: {provider: auto, model: \'\'}\n'
        '  web_extract: {provider: auto, model: \'\'}\n')
# 22a: main + reasoning + fast
write(v22g, {"provider": "custom:test-prov", "model": "Qwen3"})
write(v22g, {"reasoning_effort": "high"})
write(v22g, {"fast_mode": "fast"})
# 22e: reasoning low
write(v22g, {"reasoning_effort": "low"})
# 22g: Reset alle → letzten Output prüfen
out22g = write(v22g, {"provider": "", "model": ""})
out22g = write(v22g, {"reasoning_effort": ""})
out22g = write(v22g, {"fast_mode": ""})
reset_ok = ('default: "Qwen3"' not in out22g and 'provider: "custom:test-prov"' not in out22g
            and 'reasoning_effort:' not in out22g and 'fast_mode:' not in out22g)
check("E2E 22g-Reset-Simulation", reset_ok)

# Doppelter auxiliary-Block: auxiliary: direkt nach eingerücktem Block (vorbestehender Bug)
double_aux = ('model:\n  provider: custom:x\n  default: Y\n'
              'memory:\n  provider: holographic\n'
              'auxiliary:\n  vision: {provider: auto, model: \'\'}\n'
              '  web_extract: {provider: auto, model: \'\'}\n'
              '  compression: {provider: auto, model: \'\'}\n'
              '  skills_hub: {provider: auto, model: \'\'}\n'
              '  approval: {provider: auto, model: \'\'}\n'
              '  mcp: {provider: auto, model: \'\'}\n'
              '  title_generation: {provider: auto, model: \'\'}\n'
              '  triage_specifier: {provider: auto, model: \'\'}\n'
              '  kanban_decomposer: {provider: auto, model: \'\'}\n'
              '  profile_describer: {provider: auto, model: \'\'}\n'
              '  curator: {provider: auto, model: \'\'}\n')
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
    f.write(double_aux); dpath = f.name
try:
    os.environ["ATLAS_HERMES_CONFIG_PATH"] = dpath
    try:
        _write_hermes_aux({}, "test")  # Reset aux
        _write_hermes_aux({"vision": "test-v"}, "test")  # Set aux
        _write_hermes_main({"provider": "custom:a", "model": "B"}, "test")  # main write
        dtxt = open(dpath).read()
        aux_count = dtxt.count("auxiliary:")
        check("kein doppelter auxiliary-Block", aux_count == 1, f"found {aux_count}")
    finally:
        del os.environ["ATLAS_HERMES_CONFIG_PATH"]
finally:
    os.unlink(dpath)

print()
if FAILS:
    print("FEHLER:", len(FAILS), "->", FAILS)
    sys.exit(1)
print("ALLE BESTANDEN ✓")
