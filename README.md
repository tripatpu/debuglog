# Debug-Log Discovery Toolkit

A small pipeline for hunting exposed debug/log files during authorized bug-bounty
and pentest work. It fuzzes a target with a purpose-built wordlist using
[`ffuf`](https://github.com/ffuf/ffuf), then automatically triages the hits —
separating real, readable log files from soft-404s, SPA catch-all pages, and
WAF/error responses by inspecting each hit's **Content-Type**, **Content-Length**,
and a bounded sample of the **response body**.

> **Authorized testing only.** Use this exclusively against targets you own or are
> explicitly permitted to test (e.g. an in-scope bug-bounty program). You are
> responsible for staying within scope and rate limits.

---

## Contents

| File | Purpose |
|------|---------|
| `debug_logs_wordlist.txt` | 25,000 unique debug/log file paths (FUZZ payloads). |
| `debuglog_hunt.sh` | **Pipeline** — prompts for URL + wordlist, runs ffuf, then chains into the verifier. |
| `parse_ffuf_debuglogs.sh` | **Verifier** — parses ffuf JSON and scores each hit into TRUE_POSITIVE / review / false_positive. |
| `README.md` | This file. |

Keep all files in the same folder — `debuglog_hunt.sh` auto-locates the verifier
next to itself.

---

## Requirements

- `bash`, `curl`, `awk`, `sort`, `grep`, `xargs` (standard on Linux/macOS)
- [`ffuf`](https://github.com/ffuf/ffuf) in your `PATH` (or set `FFUF=/path/to/ffuf`)
- `jq` — optional; the verifier falls back to a grep/sed parser if it's missing

```bash
chmod +x debuglog_hunt.sh parse_ffuf_debuglogs.sh
```

---

## Quick start

Interactive (asks for URL and wordlist):

```bash
./debuglog_hunt.sh
```

Single target:

```bash
./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt
```

Many targets — one URL per line (blank lines and `#` comments allowed; non-http
lines are skipped):

```bash
./debuglog_hunt.sh -U urls.txt -w debug_logs_wordlist.txt
```

Each run creates `hunt_<timestamp>/`. For a single target it contains
`ffuf_out.json` + `debuglog_results.tsv`. For a URL list it contains one
`NN_<host>/` subdirectory per target (each with its own `ffuf_out.json` and
`debuglog_results.tsv`), plus a combined `all_true_positives.tsv` aggregating and
de-duping the confirmed hits across every host.

---

## The wordlist

`debug_logs_wordlist.txt` holds 25,000 unique, deduplicated paths ordered roughly
by likelihood (high-signal defaults first, combinatorial coverage after). It draws
on defaults seen in disclosed reports across many stacks:

- **PHP / Laravel / WordPress** — `storage/logs/laravel.log`, `wp-content/debug.log`, `php_errors.log`
- **Python / Django** — `django.log`, `gunicorn-error.log`, `celery.log`
- **Ruby / Rails** — `log/production.log`, `log/puma.log`, `log/sidekiq.log`
- **Node** — `npm-debug.log`, `logs/pm2.log`, `logs/combined.log`
- **Java / Spring** — `spring.log`, `catalina.out`, `logs/application.log`
- **.NET** — `logs/stdout.log`, `elmah.axd`, `trace.axd`
- **Servers / infra** — `var/log/nginx/error.log`, `supervisord.log`, `cloud-init.log`
- Plus generic names, rotation/date suffixes (`.log.1`, `-2026-08-10.log`, `.gz`),
  and common log directories (`logs/`, `var/log/`, `storage/logs/`, `runtime/logs/`).

You can point ffuf at any wordlist; this one is just the default.

---

## `debuglog_hunt.sh` — the pipeline

Runs ffuf, then the verifier, in one shot.

```
./debuglog_hunt.sh [options]

  -u URL        single target base URL (script appends /FUZZ)
  -U FILE       file of target URLs, one per line (overrides -u)
  -w WORDLIST   path to wordlist
  -o DIR        output directory            (default: ./hunt_<timestamp>)
  -r RATE       ffuf --rate                 (default: 50)
  -t THREADS    ffuf -t                      (default: 100)
  -m CODES      ffuf -mc match codes         (default: 200)
  -c CONC       verifier concurrency         (default: 40)
  -s SCORE      verifier true-positive score (default: 3)
  -k            insecure TLS (ffuf + verifier)
  -H 'H: V'     extra header (repeatable; passed to both stages)
  -F 'flags'    extra raw ffuf flags, e.g. '-ac -fc 404'
  -h            help
```

The ffuf invocation it builds:

```bash
ffuf -w WORDLIST:FUZZ -u BASE/FUZZ -mc 200 -c -rate 50 -t 100 -of json -o ffuf_out.json
```

Examples:

```bash
# authenticated scan, insecure TLS
./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt \
    -H 'Cookie: session=abc123' -k

# soft-404 site: match everything, auto-calibrate, filter 404s
./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt \
    -m all -F '-ac -fc 404'

# use a specific ffuf binary
FFUF=/opt/ffuf/ffuf ./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt
```

---

## `parse_ffuf_debuglogs.sh` — the verifier

Can also be run standalone against any ffuf JSON output.

```
./parse_ffuf_debuglogs.sh -i ffuf_out.json [options]

  -i FILE   ffuf JSON output (from: ffuf ... -of json -o out)   [required]
  -o FILE   results TSV                 (default: debuglog_results.tsv)
  -c N      concurrent verifiers        (default: 40)
  -b BYTES  max body bytes to sample    (default: 65536 = 64 KB)
  -s N      min score for TRUE POS      (default: 3)
  -k        insecure TLS
  -H 'H: V' extra header (repeatable)
  -x        no re-fetch; score from ffuf metadata only
  -h        help
```

### How scoring works

Each hit is scored on three axes in a single pass:

- **Content-Type** — `text/plain`, `application/octet-stream`, `x-log`, `json` add
  points; `text/html` subtracts.
- **Content-Length** — empty/tiny bodies subtract; substantial bodies add.
- **Body signatures** — log-line markers (log levels, ISO timestamps, stack traces,
  request lines, IPs) add; HTML markers and 404/login-page text subtract.

Verdicts: `TRUE_POSITIVE` (score ≥ `-s`, default 3), `false_positive` (score ≤ 0),
`review` (in between — worth a manual look).

### Performance

Built for large result sets with bounded memory:

- Streams ffuf JSON with `jq` (bodies never fully loaded into RAM)
- Verifies hits in parallel via `xargs -P`
- Fetches only the first 64 KB of each body via HTTP Range → constant memory per worker
- One `grep` pass per response; no temp-file bloat

### Output

TSV sorted by score (best first):

```
score   status  length  content-type              verdict         url                          reasons
6       200     215     application/octet-stream  TRUE_POSITIVE   https://t/logs/laravel.log   ct+ len+ logsig+
0       200     0       application/octet-stream  false_positive  https://t/logs/empty.log     ct+ empty-
-5      200     101     text/html                 false_positive  https://t/app/index.html     html- htmlbody-
```

The `reasons` column shows which signals fired, so you can tune thresholds.

---

## Tuning tips

- **Too much noise?** Raise the true-positive bar with `-s 4` (or `-s 5`), or filter
  at the ffuf stage with `-F '-ac -fc 404'`.
- **Missing real hits?** Lower `-s`, and check the `review` bucket manually.
- **Auth required?** Pass `-H 'Cookie: ...'` / `-H 'Authorization: ...'` to
  `debuglog_hunt.sh`; it forwards to both ffuf and the verifier.
- **Big scans:** bump verifier concurrency with `-c 80`, but mind the target's rate
  limits (ffuf `--rate` is separate and set via `-r`).

---

## Workflow at a glance

```
URL + wordlist ──► ffuf (Stage 1) ──► ffuf_out.json ──► verifier (Stage 2) ──► debuglog_results.tsv
                                                                                 └─► TRUE_POSITIVE list
```
