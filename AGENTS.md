# AGENTS.md

## What this repo is

`cks-notes` is a single-document study-notes repo for the Certified Kubernetes
Security Specialist (CKS) exam. **`README.md` (~2350 lines) is the entire
product.** There is no application code, no build, and no test suite — the only
"build" is linting. Almost all edits are to `README.md`.

## The real CI gate: MegaLinter (`documentation` flavor)

`.github/workflows/mega-linter.yml` runs MegaLinter on **push to any branch
except `main`** (not on PRs). Validate locally before pushing:

```bash
npx mega-linter-runner --flavor documentation
```

Linters are configured in `.mega-linter.yml`. Key behaviors an agent will
otherwise get wrong:

- **Shell inside markdown is extracted and linted.** CI pulls every ` ```bash `,
  ` ```shell `, ` ```sh ` block out of changed `.md` files (via `mq`) into one
  script and runs `shellcheck` + `shfmt` on it. So fenced shell in `README.md`
  must:
  - pass `shellcheck` (only `SC2317` is excluded)
  - be `shfmt`-formatted with `--case-indent --indent 2 --space-redirects`
  - use uppercase bash variables (e.g. `${KUBE_VERSION}`)
  - Use ` ```console ` (not ` ```bash `) for shell blocks that show output or
    `$`/`#` prompts — those are not valid runnable scripts and would fail
    shellcheck. This is the existing convention throughout `README.md`.
- **Prose wraps at 80 chars** (rumdl `MD013`), but **code blocks are exempt**
  (`.rumdl.toml`). Do not reflow long commands inside code fences.
- Markdown is linted by **`rumdl`**, not markdownlint. Links are checked by
  **`lychee`**, not markdown-link-check.

## Linter exclusions (don't fight these)

- `lychee` (`lychee.toml`, `.lycheeignore`): accepts HTTP 200/429; excludes all
  private IPs, URLs containing `$` or `%7B...%7D`, and `falco.org/*`. The many
  `192.168.x` / `localhost` URLs in the notes are intentionally not checked.
- `codespell` ignores the word `requestor` (`.codespellrc`).
- DevSkim ignores insecure-HTTP-URL (`DS137138`) and debug-code (`DS162092`)
  findings — intentional `http://` links and demo commands are allowed.
- `gitleaks` allowlists `README.md` (`.betterleaks.toml`) because the notes
  contain example tokens/hashes. Still never add real secrets.
- `CHANGELOG.md` is excluded from every linter.

## Version control workflow

- **`CHANGELOG.md` is auto-generated** by release-please (`release-type:
  simple`, runs on `main`). Never hand-edit it.
- Commit subjects: Conventional Commits, **≤ 72 chars, not capitalized**
  (`commit-check.yml`). Validated only on PRs to `main`.
- Branch names must follow Conventional Branch (`feature/`, `fix/`, `chore/`,
  …); enforced by `commit-check` (bots like renovate/dependabot are exempt).
- PR titles must be valid Conventional Commit (`semantic-pull-request.yml`).
- All GitHub Actions are SHA-pinned and use `permissions: read-all`; keep it
  that way and run `actionlint` after editing any workflow.

## Editing notes content

- Match the existing structure: `##` section per topic, intro sentence, then
  fenced commands/output. Reuse the established `bash` vs `console` split above.
- Keep the prose 80-col wrapped; let long `kubectl`/`curl` lines run inside
  fences.

Generic commit/branch/PR rules are already covered by the global instructions;
only the repo-specific deltas above matter here.
