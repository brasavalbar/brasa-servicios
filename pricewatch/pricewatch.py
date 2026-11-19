#!/usr/bin/env python3
r"""pricewatch: vigila el precio (o cualquier texto) de una página y avisa por webhook/stdout cuando cambia.
Uso: python3 pricewatch.py URL --regex '\$\s?([0-9.,]+)' [--webhook URL] [--state estado.json]
Sin dependencias externas (solo librería estándar). Pensado para cron."""
import argparse, json, os, re, sys, urllib.request

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 pricewatch/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--regex", required=True)
    ap.add_argument("--webhook"); ap.add_argument("--state", default="pricewatch_state.json")
    ap.add_argument("--below", type=float, help="avisar solo si el valor numérico baja de este umbral")
    a = ap.parse_args()
    m = re.search(a.regex, fetch(a.url), re.S)
    if not m:
        print("NO_MATCH: la expresión no encontró nada", file=sys.stderr); return 2
    val = (m.group(1) if m.groups() else m.group(0)).strip()
    state = json.load(open(a.state)) if os.path.exists(a.state) else {}
    old = state.get(a.url)
    state[a.url] = val; json.dump(state, open(a.state, "w"))
    changed = old is not None and old != val
    if a.below is not None:
        try: changed = float(val.replace(",", "")) < a.below
        except ValueError: pass
    msg = f"pricewatch: {a.url} -> {val} (antes: {old})"
    print(("CAMBIO " if changed else "SIN CAMBIO ") + msg)
    if changed and a.webhook:
        req = urllib.request.Request(a.webhook, json.dumps({"text": msg, "content": msg}).encode(), {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=30)
    return 0
sys.exit(main())
