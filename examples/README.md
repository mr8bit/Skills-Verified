# CI/CD Example Workflows

Ready-to-use workflow templates for integrating Skills Verified into GitHub Actions and GitLab CI pipelines.

## GitHub Actions

| File | Description |
|---|---|
| [github-actions/basic.yml](github-actions/basic.yml) | Minimal scan with a threshold gate — suitable for most projects |
| [github-actions/full.yml](github-actions/full.yml) | All features: PR comments, badge generation, artifact upload, commented-out Docker variant |
| [github-actions/monorepo.yml](github-actions/monorepo.yml) | Matrix strategy scanning multiple services/plugins in parallel |

## GitLab CI

| File | Description |
|---|---|
| [gitlab-ci/basic.yml](gitlab-ci/basic.yml) | Minimal include + extends with threshold gate |
| [gitlab-ci/full.yml](gitlab-ci/full.yml) | Full features: stages, MR comments, badge, artifacts, commented-out Docker variant |
| [gitlab-ci/monorepo.yml](gitlab-ci/monorepo.yml) | `parallel:matrix` scanning multiple source directories |

---

## Configuration

### Threshold options

Both GitHub Actions inputs and GitLab CI variables control when a scan is considered failed.

| GitHub Actions input | GitLab CI variable | Default | Description |
|---|---|---|---|
| `threshold` | `SV_THRESHOLD` | `0` | Minimum numeric score (0-100). Fail if score is below this value. |
| `threshold-grade` | `SV_THRESHOLD_GRADE` | — | Minimum grade (A/B/C/D/F). Fail if grade is worse. Either condition triggers failure. |

Example: `threshold: 70` + `threshold-grade: C` fails the build when the score is below 70 **or** the grade is D/F.

### Other options

| GitHub Actions input | GitLab CI variable | Description |
|---|---|---|
| `source` | `SV_SOURCE` | Path to scan. Defaults to `.` (repository root). |
| `skip` | `SV_SKIP` | Comma-separated list of analyzers to skip (e.g. `llm,semgrep`). |
| `only` | `SV_ONLY` | Run only these analyzers (e.g. `pattern,guardrails`). |
| `use-docker` | `SV_USE_DOCKER` | Use the pre-built Docker image instead of pip install. |
| `comment-on-pr` | `SV_COMMENT_ON_MR` | Post a scan summary as a PR/MR comment (`true`/`false`). |
| `comment-style` | `SV_COMMENT_STYLE` | Comment verbosity: `full` (all findings) or `summary` (scores only). |
| `generate-badge` | `SV_GENERATE_BADGE` | Write a `trust-badge.json` shields.io endpoint file. |
| `python-version` | — | Python version for pip-based install (GitHub Actions only). |

---

## Badge Setup

When `generate-badge: true` (or `SV_GENERATE_BADGE: "true"`) is set, the action writes a `trust-badge.json` file compatible with the [shields.io endpoint](https://shields.io/endpoint) format.

Upload `trust-badge.json` to a publicly accessible URL (e.g. GitHub Pages, Gist, S3) and then add the badge to your README:

```markdown
[![Trust Score](https://img.shields.io/endpoint?url=https://your-host/path/to/trust-badge.json)](https://github.com/your-org/your-repo)
```

The badge shows the current grade (A–F) and colour-codes it automatically:

| Grade | Colour |
|---|---|
| A | brightgreen |
| B | green |
| C | yellow |
| D | orange |
| F | red |
