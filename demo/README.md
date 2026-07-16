# WGPL demos (VHS)

Offline terminal recordings for the README landing page. No WireGuard kernel,
no `wgpl apply` — admin-laptop workflow with optional remote `syncconf` mock.

## Prerequisites

- [VHS](https://github.com/charmbracelet/vhs) (`vhs`)
- `jq`, `uv`
- Monospace font: **DejaVu Sans Mono** (box-drawing / QR friendly)

## Render

```bash
cd demo
make all          # all five GIFs
make style-pass   # only 01 (visual QA)
make clean
```

Outputs land in `output/`. Tapes share a Catppuccin Mocha chrome (rounded
window bar, margin halo). Prompt is Catppuccin truecolor: blue `~` + pink `❯`
(via `PROMPT_COMMAND`) so it stays distinct from lavender typed text.

Render setup puts the project `.venv/bin` on `PATH` so `wgpl` is the real
installed CLI (same binary users get after `uv tool install` / `pip install`).
Tape 01 shows the install hint + `wgpl --version` before any mutations.

## Scenarios

| GIF | Story | Sysadmin flow |
|-----|--------|----------------|
| [01_quickstart.gif](output/01_quickstart.gif) | Peer + config + QR | `peer add` → `peer list` → capture ID → `config` / `qr` |
| [02_split_tunnel.gif](output/02_split_tunnel.gif) | Cloud VPC split tunnel | declare policy → `list` → `peer explain` |
| [03_branch_offices.gif](output/03_branch_offices.gif) | NY ↔ London AllowedIPs | two `subnet_router`s → `list` → `explain` both → `validate` |
| [04_mixed_topology.gif](output/04_mixed_topology.gif) | Laptops + three branches | build topo → `list` → `explain` gateway → `validate --strict` |
| [05_remote_sync.gif](output/05_remote_sync.gif) | `export \| ssh … wg syncconf` | declare → `interface export` → remote sync (mocked) |

Peer refs are never “magic”: demos show `peer list`, then a visible
`P=$(wgpl -j peer list … | jq …)` (or `NY=` / `LDN=`) before `$P` is used.

## Versioning

Commit the full `demo/` tree: source (`tapes/`, `scripts/`, `Makefile`,
this README) and compiled GIFs under `output/`. Relative paths in the project
README must resolve on GitHub after clone. Do not use Git LFS until the demo
pack grows well past ~10 MB.

## When to re-render

Re-render manually with `make all` (or a single target) when:

- human-facing CLI output shown in a tape changes (`peer list` columns/IDs,
  `explain`, QR, validate flags, prompts);
- tape chrome/branding changes (theme, font, window bar);
- preparing a minor/major release whose marketing story should match the tag.

Do **not** re-render and re-commit on every patch bump with no visible UX change.
Do **not** wire VHS into CI for every PR in this phase — GIFs are a public UX
snapshot for the tag, not a substitute for tests.

Prefer one `docs(demo): …` commit for GIF refreshes, or include regenerated
GIFs in the same commit as the CLI change that invalidates them.
