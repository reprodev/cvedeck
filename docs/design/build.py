"""Render the fleet view in three design directions for side-by-side comparison.

A first pass swapped only colour tokens across one shared template, which made
the three read as palette variants rather than as directions. Each now carries
its own structural signature, because that is what actually distinguishes them:

  A  a fixed gutter lamp and an otherwise quiet instrument panel
  B  monospace as the structural voice, cards dissolved into ruled rows
  C  the hostname as a stamped asset tag, the row as a tag record

Each page renders the findings table twice -- severity as a single-hue ramp with
red reserved for exploitation, and as the familiar four hues -- so that decision
can be judged directly rather than argued about.

Evaluation artifact, not shipped code. Published as a record of the decision;
see README.md in this directory.
"""

from __future__ import annotations

import io
from pathlib import Path

OUT = Path(__file__).parent

HOSTS = [
    ("db-primary.lan",   1, 5, 3, 0, 0, "1d",    "ok"),
    ("web-01.lan",       1, 4, 2, 0, 0, "1h",    "ok"),
    ("dc-01.lan",        1, 3, 3, 0, 0, "3d",    "ok"),
    ("app-alma.lan",     0, 4, 3, 0, 0, "2d",    "partial"),
    ("cache-01.lan",     0, 3, 4, 0, 0, "1h",    "ok"),
    ("build-arm.lan",    0, 2, 2, 0, 0, "1h",    "ok"),
    ("edge-proxy.lan",   0, 2, 2, 0, 0, "1h",    "ok"),
    ("nas-01.lan",       0, 1, 3, 0, 0, "1mo",   "stale"),
    ("web-02.lan",       0, 1, 2, 0, 0, "1h",    "ok"),
    ("new-host.lan",  None, 0, 0, 0, 0, "never", "never"),
    ("pi-sensor.lan", None, 0, 0, 0, 0, "2d",    "auth"),
    ("rdp-gw.lan",    None, 0, 0, 0, 0, "1d",    "conn"),
]

SEV = {
    "ramp": {"label": "Single-hue ramp — red reserved for exploitation",
             "critical": "#C9A227", "high": "#A8871F",
             "medium": "#846A18", "low": "#5E4C11"},
    "hues": {"label": "Four distinct hues — the familiar treatment",
             "critical": "#E5484D", "high": "#E8823A",
             "medium": "#D9B32C", "low": "#4FA97D"},
}

# --------------------------------------------------------------------------- #
# Per-direction structural CSS. This is where the directions actually differ.
# --------------------------------------------------------------------------- #

CSS_A = """
/* A: the gutter lamp. A fixed-width first column carrying one physical mark,
   read like a status LED on rack equipment. Everything else stays quiet so the
   lamp is the only thing competing for attention. */
.c-kev{width:74px;box-shadow:inset 1px 0 0 var(--line)}
.lamp{font-size:15px;display:inline-block;width:16px;text-align:center}
tbody tr{transition:background .1s}
.cell{padding:15px 17px}
th{padding:10px 13px}
td{padding:11px 13px}
.host{letter-spacing:-.01em}
"""

CSS_B = """
/* B: monospace as the structural voice. Cards dissolve -- no panel fills, no
   radius, rules only. The gutter carries one character per row, read like a
   diff gutter or the permission column of `ls -l`. Prose face appears only in
   the thesis line and the strip. */
.host,th,.chip,.cell-k,.cell-v,.cell-u,.tag,.c-age,.n,.n-zero{font-family:var(--mono)}
.triage{background:none;border:0;border-top:1px solid var(--line);
  border-bottom:1px solid var(--line);gap:0;border-radius:0}
.cell{background:none;border-right:1px solid var(--line);padding:14px 18px}
.cell:last-child{border-right:0}
.strip{background:none;border:0;border-bottom:1px solid var(--line);
  border-radius:0;padding:10px 0}
.chip{background:none;border-radius:0;border-color:var(--line)}
.chip.on{border-color:var(--accent);color:var(--accent)}
.tablewrap{border:0;border-radius:0}
th{background:none;padding:8px 10px 8px 0;border-bottom:1px solid var(--line)}
td{padding:7px 10px 7px 0;border-bottom:1px solid color-mix(in srgb,var(--line) 55%,transparent)}
tbody tr:hover td{background:none;color:var(--text)}
tbody tr:hover .gut{color:var(--accent)}
.gut{display:inline-block;width:20px;color:var(--faint);font-family:var(--mono)}
.c-host{padding-left:0}
.c-kev{width:78px}
.row-hit td{background:none}
.row-hit .gut{color:var(--alarm)}
.row-hit .host{color:var(--text);font-weight:600}
.tag{border-radius:0}
"""

CSS_C = """
/* C: the hostname as a stamped asset tag -- bordered, inset, letterspaced,
   set in Archivo Expanded. The motif is confined to hostnames and never spreads
   to buttons or chips, which is what stops it turning twee. */
.host{font-family:var(--sans);font-variation-settings:'wdth' 118;
  font-weight:600;font-size:11.5px;letter-spacing:.10em;text-transform:uppercase;
  display:inline-block;padding:4px 10px 3px;border:1px solid var(--line);
  border-left:3px solid var(--dim);background:var(--raised);border-radius:1px;
  color:var(--text)}
.row-hit .host{border-left-color:var(--alarm)}
tr.st-never .host,tr.st-auth .host,tr.st-conn .host{color:var(--dim);
  border-left-color:var(--faint)}
.c-host{padding:8px 12px}
td{padding:8px 12px}
.cell-k{font-variation-settings:'wdth' 112;font-weight:600}
.tag{border-radius:1px;font-variation-settings:'wdth' 110}
.c-kev{width:82px}
.lamp{font-size:12px}
"""

DIRECTIONS = {
    "a-field-instrument": {
        "name": "A — Field instrument",
        "thesis": "Colour is scarce, so it means something. Only confirmed "
                  "exploitation gets the alarm colour; severity steps back.",
        "fonts": ("Public+Sans:wght@400;500;600;700",
                  "IBM+Plex+Mono:wght@400;500;600"),
        "sans": "'Public Sans'", "mono": "'IBM Plex Mono'",
        "tokens": {"bg": "#17171A", "surface": "#1E1E22", "raised": "#25252B",
                   "line": "#33333A", "text": "#E8E6E1", "dim": "#8A8A93",
                   "faint": "#5C5C64", "alarm": "#FF4D2E", "accent": "#C9A227",
                   "radius": "3px"},
        "marks": ("▪", "▫", "·"), "css": CSS_A, "gutter": False,
    },
    "b-terminal-ledger": {
        "name": "B — Terminal ledger",
        "thesis": "Monospace as the structural voice. Cards dissolve into ruled "
                  "rows; a gutter mark carries state like a diff column.",
        "fonts": ("Instrument+Sans:wght@400;500;600",
                  "Spline+Sans+Mono:wght@400;500;600;700"),
        "sans": "'Instrument Sans'", "mono": "'Spline Sans Mono'",
        "tokens": {"bg": "#0E1013", "surface": "#0E1013", "raised": "#161A1F",
                   "line": "#2A2F36", "text": "#E4E0D6", "dim": "#7E8590",
                   "faint": "#565D66", "alarm": "#E5484D", "accent": "#7FB8A4",
                   "radius": "0px"},
        "marks": ("●", "○", "?"), "css": CSS_B, "gutter": True,
    },
    "c-rack-and-label": {
        "name": "C — Rack and label",
        "thesis": "A fleet is physical. The hostname is a stamped asset tag, "
                  "the row is the tag record.",
        "fonts": ("Archivo:wdth,wght@62..125,400..700",
                  "IBM+Plex+Mono:wght@400;500;600"),
        "sans": "'Archivo'", "mono": "'IBM Plex Mono'",
        "tokens": {"bg": "#1C1E1D", "surface": "#262927", "raised": "#2F332F",
                   "line": "#3C403D", "text": "#F2F1EC", "dim": "#8C918C",
                   "faint": "#5F645F", "alarm": "#D94F30", "accent": "#E8C547",
                   "radius": "2px"},
        "marks": ("■", "□", "—"), "css": CSS_C, "gutter": False,
    },
}


def kev_cell(kev, marks, alarm) -> str:
    """Three states, three readings. Never a zero standing in for 'unchecked'."""
    on, off, unknown = marks
    if kev is None:
        return f'<span class="lamp lamp-unknown" title="Not checked">{unknown}</span>'
    if kev > 0:
        return (f'<span class="lamp lamp-on" style="color:{alarm}">{on}</span>'
                f'<span class="kev-n">{kev}</span>')
    return f'<span class="lamp lamp-off">{off}</span><span class="kev-n">0</span>'


def table(d: dict, sev: dict, key: str) -> str:
    marks, alarm, gut = d["marks"], d["tokens"]["alarm"], d["gutter"]
    rows = []
    for host, kev, crit, high, med, low, age, state in HOSTS:
        cells = ""
        for k, v in (("critical", crit), ("high", high),
                     ("medium", med), ("low", low)):
            cls = "n-zero" if v == 0 else "n"
            style = f'style="color:{sev[k]}"' if v > 0 else ""
            cells += (f'<td class="num" data-label="{k[:4].title()}">'
                      f'<span class="{cls}" {style}>{v}</span></td>')
        badge = {"partial": '<i class="tag tag-warn">Partial</i>',
                 "stale": '<i class="tag tag-warn">Stale</i>',
                 "never": '<i class="tag tag-mute">New</i>',
                 "auth": '<i class="tag tag-bad">Auth</i>',
                 "conn": '<i class="tag tag-bad">Down</i>'}.get(state, "")
        mark = marks[0] if kev else (marks[1] if kev == 0 else marks[2])
        gutter = f'<span class="gut">{mark}</span>' if gut else ""
        rows.append(f"""
        <tr class="{'row-hit ' if kev else ''}st-{state}">
          <td class="c-host" data-label="Host">{gutter}<span class="host">{host}</span> {badge}</td>
          <td class="c-kev" data-label="Exploited">{kev_cell(kev, marks, alarm)}</td>
          {cells}
          <td class="c-age {'age-stale' if state == 'stale' else ''}"
              data-label="Scanned">{age}</td>
        </tr>""")
    return f"""
    <p class="sev-caption">{sev['label']}</p>
    <div class="tablewrap"><table>
      <thead><tr>
        <th class="c-host">Host</th><th class="c-kev">Exploited</th>
        <th class="num">Crit</th><th class="num">High</th>
        <th class="num">Med</th><th class="num">Low</th>
        <th class="c-age">Scanned</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>"""


def page(d: dict) -> str:
    t, marks = d["tokens"], d["marks"]
    fonts = "&family=".join(d["fonts"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CveDeck — {d['name']}</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family={fonts}&display=swap" rel="stylesheet">
<style>
:root{{--bg:{t['bg']};--surface:{t['surface']};--raised:{t['raised']};
--line:{t['line']};--text:{t['text']};--dim:{t['dim']};--faint:{t['faint']};
--alarm:{t['alarm']};--accent:{t['accent']};--r:{t['radius']};
--sans:{d['sans']},system-ui,sans-serif;--mono:{d['mono']},ui-monospace,monospace}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:1180px;margin:0 auto;padding:28px 22px 64px}}
.top{{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;min-width:0;
padding-bottom:16px;border-bottom:1px solid var(--line)}}
.brand{{font-family:var(--mono);font-size:18px;font-weight:600;letter-spacing:-.02em}}
.brand b{{color:var(--alarm);font-weight:600}}
.ver{{font-family:var(--mono);font-size:11px;color:var(--faint)}}
.thesis{{flex:1 1 300px;min-width:0;color:var(--dim);font-size:12.5px;max-width:56ch}}
.triage{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;
background:var(--line);border:1px solid var(--line);border-radius:var(--r);
margin:22px 0 14px;overflow:hidden}}
.cell{{background:var(--surface);padding:13px 15px;min-width:0}}
.cell-u,.cell-k{{overflow-wrap:anywhere}}
.cell-k{{font-family:var(--mono);font-size:10px;letter-spacing:.09em;
text-transform:uppercase;color:var(--dim)}}
.cell-v{{font-family:var(--mono);font-size:27px;font-weight:600;line-height:1.15;
margin-top:3px;font-variant-numeric:tabular-nums}}
.cell-u{{font-size:11px;color:var(--faint);font-family:var(--mono)}}
.cell.hit .cell-v{{color:var(--alarm)}}
.cell.hit{{box-shadow:inset 2px 0 0 var(--alarm)}}
.cell.warn .cell-v{{color:var(--accent)}}
.strip{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:9px 15px;
border:1px solid var(--line);border-radius:var(--r);background:var(--surface);
margin-bottom:22px;font-size:12.5px;color:var(--dim)}}
.strip b{{color:var(--text);font-family:var(--mono)}}
.chips{{display:flex;gap:6px;margin-left:auto;flex-wrap:wrap}}
.chip{{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:99px;
border:1px solid var(--line);color:var(--dim);background:var(--raised)}}
.chip.on{{color:var(--text);border-color:var(--dim)}}
.sev-caption{{font-family:var(--mono);font-size:10px;letter-spacing:.09em;
text-transform:uppercase;color:var(--faint);margin:26px 0 8px}}
.tablewrap{{border:1px solid var(--line);border-radius:var(--r);overflow:hidden}}
table{{width:100%;border-collapse:collapse}}
th{{font-family:var(--mono);font-size:10px;letter-spacing:.09em;
text-transform:uppercase;color:var(--dim);text-align:left;font-weight:500;
padding:9px 12px;background:var(--raised);border-bottom:1px solid var(--line)}}
td{{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:middle}}
tr:last-child td{{border-bottom:0}}
tbody tr:hover td{{background:var(--raised)}}
.num{{text-align:right;width:58px}}
th.num{{text-align:right}}
.n{{font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums}}
.n-zero{{font-family:var(--mono);color:var(--faint);font-variant-numeric:tabular-nums}}
.host{{font-family:var(--mono);font-size:13px;color:var(--text)}}
.c-kev{{width:96px;white-space:nowrap}}
.c-age{{width:104px;padding-left:14px;font-family:var(--mono);font-size:12px;color:var(--dim)}}
.age-stale{{color:var(--accent)}}
.lamp{{font-size:13px;display:inline-block;width:14px}}
.lamp-off{{color:var(--faint)}}
.lamp-unknown{{color:var(--faint);opacity:.45}}
.kev-n{{font-family:var(--mono);font-size:12px;color:var(--dim);margin-left:2px}}
.row-hit td{{background:color-mix(in srgb,var(--alarm) 6%,transparent)}}
.tag{{font-family:var(--mono);font-style:normal;font-size:9.5px;padding:1px 5px;
border-radius:2px;letter-spacing:.05em;text-transform:uppercase;margin-left:5px;
border:1px solid var(--line);color:var(--dim)}}
.tag-warn{{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}}
.tag-bad{{color:var(--alarm);border-color:color-mix(in srgb,var(--alarm) 40%,transparent)}}
{d['css']}
@media (max-width:700px){{
.wrap{{padding:20px 14px 48px}}
.triage{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.chips{{margin-left:0}}
thead{{position:absolute;left:-9999px}}
.tablewrap{{border:0;border-radius:0;overflow:visible}}
table,tbody,tr,td{{display:block;width:auto}}
tr{{border:1px solid var(--line);border-radius:var(--r);margin-bottom:8px;
padding:10px 12px;background:var(--surface)}}
td{{border:0;padding:2px 0;display:flex;justify-content:space-between;
align-items:baseline;gap:12px;min-width:0}}
td>*{{min-width:0;overflow-wrap:anywhere}}
td::before{{content:attr(data-label);font-family:var(--mono);font-size:10px;
letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}}
.c-host{{display:block;margin-bottom:7px;padding-bottom:7px;
border-bottom:1px solid var(--line)}}
.c-host::before{{display:none}}
.num,.c-kev,.c-age{{width:auto}}
.row-hit{{box-shadow:inset 2px 0 0 var(--alarm)}}
.row-hit td{{background:none}}
}}
@media (max-width:480px){{.triage{{grid-template-columns:minmax(0,1fr)}}}}
</style></head><body><div class="wrap">
<div class="top"><span class="brand">cve<b>deck</b></span>
<span class="ver">{d['name']}</span><span class="thesis">{d['thesis']}</span></div>
<div class="triage">
<div class="cell hit"><div class="cell-k">{marks[0]} Actively exploited</div>
<div class="cell-v">3</div><div class="cell-u">3 hosts · 3 on CISA KEV</div></div>
<div class="cell"><div class="cell-k">Critical findings</div>
<div class="cell-v">9</div><div class="cell-u">9 hosts · 25 findings</div></div>
<div class="cell"><div class="cell-k">High findings</div>
<div class="cell-v">9</div><div class="cell-u">9 hosts · 24 findings</div></div>
<div class="cell warn"><div class="cell-k">Needs attention</div>
<div class="cell-v">4</div><div class="cell-u">2 failed · 1 stale · 1 new</div></div>
</div>
<div class="strip"><span><b>49</b> findings across <b>12</b> hosts</span>
<span class="chips"><span class="chip on">All 49</span><span class="chip">Critical 25</span>
<span class="chip">High 24</span><span class="chip">Medium 0</span>
<span class="chip">Low 0</span></span></div>
{table(d, SEV['ramp'], 'ramp')}
{table(d, SEV['hues'], 'hues')}
</div></body></html>"""


def main() -> None:
    for slug, d in DIRECTIONS.items():
        io.open(OUT / f"{slug}.html", "w", encoding="utf-8",
                newline="\n").write(page(d))
        print("wrote", f"{slug}.html")


if __name__ == "__main__":
    main()
