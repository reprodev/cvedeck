# Design directions

Three static mockups of the fleet view, made before any component was rebuilt.
They are kept here as a record of how the current design was chosen, and they
are the artifacts behind [Chapter 10 of the development
story](../DEVELOPMENT_STORY.md#chapter-10--the-palette-was-never-really-ours-v052).

| | Direction | Structural signature |
| :--- | :--- | :--- |
| [A](a-field-instrument.html) | Field instrument | A fixed gutter lamp, and an otherwise quiet instrument panel |
| [B](b-terminal-ledger.html) | Terminal ledger | Monospace as the structural voice, cards dissolved into ruled rows |
| [C](c-rack-and-label.html) | Rack and label | The hostname as a stamped asset tag, the row as a tag record |

**C won**, and the dashboard's current language comes from it.

Open the HTML files directly in a browser — they are self-contained, fetch
nothing, and need no server. [`build.py`](build.py) generates all three from one
data set.

## Why three mockups rather than a discussion

Two things were settled here that argument had not settled.

**The first pass proved nothing, and that was the lesson.** It swapped only
colour tokens across one shared template, so the three rendered as three tints
of the same dashboard — a fair comparison of palettes and no comparison at all of
directions. A direction that lives entirely in its colour values is a skin. Each
mockup was redone with its own structural signature, and the difference became
obvious immediately.

**The severity question decided itself on screen.** Each page renders the
findings table twice: severity as four distinct hues, and severity as a single
amber ramp with red reserved for exploitation. With four hues, nine red Critical
counts and three red exploitation marks compete on the same screen and the eye
resolves neither — the actively exploited hosts are simply lost. With the ramp
they are unmissable.

Two releases had gone into establishing that exploitation outranks severity, and
the palette had been quietly arguing the opposite the whole time. Putting the two
renderings side by side was more convincing than any amount of reasoning about
it, which is why these files are published rather than deleted.

## Status

Evaluation artifacts, not shipped code. They are a snapshot of the moment the
decision was made and are deliberately **not** kept in step with the dashboard —
the live design system is the one in `frontend/src`, and where these disagree
with it, the code is right and these are history.
