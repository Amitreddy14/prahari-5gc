# design.md — visual identity of the Prahari SOC console

The console is a tool an analyst stares at for hours during an incident. Every
choice favours fast scanning, low eye strain and unambiguous severity.

## 1. Principles

1. **Calm until it matters.** Neutral surfaces. Colour is reserved for severity and state.
2. **Evidence first.** Every alert shows the raw facts (messages, IDs, timings) next to the AI summary, and the summary always marks itself as generated.
3. **Dense but legible.** Tables and timelines over cards. Monospace for protocol data.
4. **Never colour alone.** Severity always pairs colour with a label and an icon shape.

## 2. Theme

Dark-first (NOC rooms are dim), with a full light theme. All colours are tokens.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0E1116` | `#F7F8FA` | Page |
| `--surface` | `#161B22` | `#FFFFFF` | Panels, tables |
| `--surface-2` | `#1F2630` | `#EEF1F5` | Hover, selected row |
| `--border` | `#2A3240` | `#D9DEE5` | Dividers |
| `--text` | `#E6EAF0` | `#1A1F27` | Body |
| `--text-muted` | `#8B95A5` | `#5B6575` | Labels, timestamps |
| `--accent` | `#3BA7A0` | `#1F7A74` | Links, focus ring, primary buttons (teal: "sentry") |

### Severity

| Level | Colour (dark / light) | Icon | Meaning |
|---|---|---|---|
| Critical | `#F25C54` / `#C2352E` | filled octagon | Active attack affecting sessions now |
| High | `#F2A541` / `#B86E0B` | triangle | Attack pattern confirmed, impact unclear |
| Medium | `#E3D26F` / `#8A7A12` | diamond | Suspicious, needs a look |
| Low | `#6FA8DC` / `#2F6FA8` | circle | Informational anomaly |
| Resolved | `#7BC47F` / `#2E7D32` | check | Closed by an analyst |

Interface tags (N2, N4, SBI) use outlined chips in `--text-muted`, not colour.

## 3. Typography

| Role | Font | Size / weight |
|---|---|---|
| UI text | Inter | 14px / 400, 500 for labels |
| Headings | Inter | 20 / 16 / 14px, weight 600 |
| Protocol data, IDs, hex, timestamps | JetBrains Mono | 13px / 400 |
| Numbers in tables | Inter with `font-variant-numeric: tabular-nums` | 14px |

Timestamps are always UTC in ISO-8601 with milliseconds, with local time on hover.

## 4. Spacing and layout

- 4px base grid: spacing tokens 4, 8, 12, 16, 24, 32.
- Radius: 6px controls, 8px panels. No shadows; borders separate surfaces.
- Layout: left rail (navigation) · main (alert timeline) · right drawer (alert detail + triage).
- Minimum target size 32px; full keyboard navigation (j/k to move through alerts, Enter to open, Esc to close).

## 5. Core components

| Component | Notes |
|---|---|
| Alert timeline | Virtualised table: time, severity, attack class, interface chip, affected UE/session count, status. Live-updating rows fade in; no layout jumps. |
| Alert detail drawer | Header (severity, class, time window) → evidence table (event list, monospace) → "AI triage" panel with a *Generated* badge and model name → analyst actions (acknowledge, resolve, add note). |
| Session ladder | Sequence diagram of one UE's or session's messages across gNB/AMF/SMF/UPF, with the anomalous step highlighted. The signature visual of the product. |
| Rate sparkline | Per-interface message rate, last 15 minutes, with the alert window shaded. |
| Detector badge | Shows which detector fired (rule / IForest / sequence) and its score. |
| Empty and error states | Plain sentences that say what is wrong and what to do: "Probe not sending events: check `prahari-probe` health". |

## 6. Motion

Only for state changes: 150ms fade for new rows, 200ms drawer slide. Respect
`prefers-reduced-motion`. Nothing loops or pulses, except a single 1s highlight
when a *critical* alert arrives.

## 7. Accessibility

WCAG 2.1 AA contrast in both themes, visible focus ring (`--accent`, 2px),
screen-reader labels on severity icons, and no information carried by colour alone.
