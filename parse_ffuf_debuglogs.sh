#!/usr/bin/env bash
#
# parse_ffuf_debuglogs.sh
# ---------------------------------------------------------------------------
# Triage ffuf output for exposed debug/log files and separate TRUE POSITIVES
# from noise (SPA catch-alls, soft-404s, WAF pages) by inspecting each hit's
# Content-Type, Content-Length and a bounded sample of the response BODY.
#
# Designed for speed + low memory:
#   * streams the ffuf JSON with jq (no full in-RAM parse of bodies)
#   * verifies hits in parallel (xargs -P)
#   * fetches only the first N KB of each body (HTTP Range) -> constant memory
#   * scores with a single grep pass per response, no temp bloat
#
# Usage:
#   ./parse_ffuf_debuglogs.sh -i ffuf_output.json [options]
#
# Options:
#   -i FILE   ffuf JSON output file (from: ffuf ... -o out -of json)   [required]
#   -o FILE   results TSV               (default: debuglog_results.tsv)
#   -c N      concurrent verifiers      (default: 40)
#   -b BYTES  max body bytes to sample  (default: 65536  = 64 KB)
#   -s N      min score for TRUE POS    (default: 3)
#   -k        insecure TLS (curl -k)
#   -H 'H: V' extra header (repeatable, e.g. auth cookie)
#   -x        no re-fetch; score using only ffuf's length/content-type
#   -h        help
#
# Output columns (TSV): score status length content-type verdict url reasons
# ---------------------------------------------------------------------------
set -euo pipefail

# ---- defaults -------------------------------------------------------------
INPUT=""; OUT="debuglog_results.tsv"; CONC=40; MAXB=65536; MINSCORE=3
INSECURE=""; NOFETCH=0; EXTRA_HEADERS=()

usage(){ sed -n '2,40p' "$0"; exit "${1:-0}"; }

while getopts ":i:o:c:b:s:kH:xh" opt; do
  case "$opt" in
    i) INPUT=$OPTARG ;;
    o) OUT=$OPTARG ;;
    c) CONC=$OPTARG ;;
    b) MAXB=$OPTARG ;;
    s) MINSCORE=$OPTARG ;;
    k) INSECURE="-k" ;;
    H) EXTRA_HEADERS+=("-H" "$OPTARG") ;;
    x) NOFETCH=1 ;;
    h) usage 0 ;;
    :) echo "Missing arg for -$OPTARG" >&2; usage 1 ;;
    *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
  esac
done

[[ -n "$INPUT" ]] || { echo "[-] -i <ffuf.json> is required" >&2; usage 1; }
[[ -r "$INPUT" ]] || { echo "[-] cannot read: $INPUT" >&2; exit 1; }
command -v curl >/dev/null || { echo "[-] curl not found" >&2; exit 1; }

# ---- 1. extract hits from ffuf JSON --------------------------------------
# Prefer jq; fall back to a tolerant grep/sed parser if jq is missing.
extract(){
  if command -v jq >/dev/null 2>&1; then
    jq -r '.results[] | [(.url//""),(.status//0),(.length//0),(."content-type"//"")]
           | @tsv' "$INPUT"
  else
    tr '}' '}\n' < "$INPUT" | grep '"url"' | while IFS= read -r line; do
      u=$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' <<<"$line")
      s=$(sed -n 's/.*"status":\([0-9]*\).*/\1/p'  <<<"$line")
      l=$(sed -n 's/.*"length":\([0-9]*\).*/\1/p'  <<<"$line")
      ct=$(sed -n 's/.*"content-type":"\([^"]*\)".*/\1/p' <<<"$line")
      [[ -n "$u" ]] && printf '%s\t%s\t%s\t%s\n' "$u" "${s:-0}" "${l:-0}" "${ct:-}"
    done
  fi
}

TOTAL=$(extract | grep -c . || true)
echo "[*] ffuf hits parsed : $TOTAL"
[[ "$TOTAL" -gt 0 ]] || { echo "[-] no hits in $INPUT"; exit 0; }

# ---- 2. scorer (runs once per hit, in a subshell for xargs) --------------
export MAXB INSECURE NOFETCH MINSCORE
export EXTRA_HDR_STR="${EXTRA_HEADERS[*]:-}"

score_one(){
  local url status length ctype
  IFS=$'\t' read -r url status length ctype <<<"$1"
  local score=0 reasons="" body="" hdr="" clen="$length" ct="$ctype"

  if [[ "$NOFETCH" -eq 0 ]]; then
    local resp
    resp=$(curl -sS $INSECURE --max-time 15 -r "0-$((MAXB-1))" -D - \
                 ${EXTRA_HDR_STR:+$EXTRA_HDR_STR} "$url" 2>/dev/null || true)
    hdr=$(printf '%s' "$resp" | sed -n '1,/^\r\{0,1\}$/p')
    body=$(printf '%s' "$resp" | sed '1,/^\r\{0,1\}$/d')
    local hct hcl
    hct=$(printf '%s' "$hdr" | tr 'A-Z' 'a-z' | sed -n 's/^content-type:[[:space:]]*\([^;[:space:]]*\).*/\1/p' | head -1)
    hcl=$(printf '%s' "$hdr" | tr 'A-Z' 'a-z' | sed -n 's/^content-length:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
    [[ -n "$hct" ]] && ct="$hct"
    [[ -n "$hcl" ]] && clen="$hcl"
  fi

  # ---- content-type signal ----
  case "$ct" in
    text/plain|application/octet-stream|application/x-log|text/x-log|application/json)
        score=$((score+2)); reasons+="ct+ ";;
    text/html*|application/xhtml*)
        score=$((score-2)); reasons+="html- ";;
  esac

  # ---- length signal ----
  if [[ "${clen:-0}" =~ ^[0-9]+$ ]]; then
    if   [[ "$clen" -eq 0 ]];   then score=$((score-2)); reasons+="empty- "
    elif [[ "$clen" -lt 32 ]];  then score=$((score-1)); reasons+="tiny- "
    elif [[ "$clen" -gt 200 ]]; then score=$((score+1)); reasons+="len+ "
    fi
  fi

  # ---- body signal (only if we fetched) ----
  if [[ "$NOFETCH" -eq 0 && -n "$body" ]]; then
    local pos neg
    pos=$(printf '%s' "$body" | grep -Eic \
      '(\b(DEBUG|INFO|WARN(ING)?|ERROR|FATAL|TRACE|NOTICE|CRITICAL)\b)|(\[?[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2})|(Traceback \(most recent call last\))|(Stack trace:)|(at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.(java|kt|rb|php|py):[0-9]+\))|(Exception|Fatal error|Warning:|Notice:|Deprecated:)|((GET|POST|PUT|DELETE) /[^ ]* HTTP/)|(([0-9]{1,3}\.){3}[0-9]{1,3})' \
      || true)
    neg=$(printf '%s' "$body" | grep -Eic \
      '(<!doctype html|<html|<head|<body|<title|<script|<div)|(404 Not Found|403 Forbidden|Access Denied|Page Not Found|Sign ?in|Login</)' \
      || true)
    [[ "${pos:-0}" -ge 1 ]] && { score=$((score+3)); reasons+="logsig+ "; }
    [[ "${pos:-0}" -ge 5 ]] && { score=$((score+1)); reasons+="logsig++ "; }
    [[ "${neg:-0}" -ge 1 ]] && { score=$((score-3)); reasons+="htmlbody- "; }
  fi

  local verdict="review"
  if   [[ "$score" -ge "$MINSCORE" ]]; then verdict="TRUE_POSITIVE"
  elif [[ "$score" -le 0 ]];           then verdict="false_positive"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$score" "$status" "${clen:-$length}" "${ct:-?}" "$verdict" "$url" "${reasons:-.}"
}
export -f score_one

echo "[*] verifying (conc=$CONC, sample=${MAXB}B, refetch=$([[ $NOFETCH -eq 1 ]] && echo no || echo yes)) ..."

# ---- 3. run verifiers in parallel, stream to sorter -----------------------
HEADER=$'score\tstatus\tlength\tcontent-type\tverdict\turl\treasons'
{
  extract \
   | xargs -d '\n' -I{} -P "$CONC" bash -c 'score_one "$@"' _ {} \
   | sort -t$'\t' -k1,1nr -k3,3nr
} > "$OUT.body"

{ printf '%s\n' "$HEADER"; cat "$OUT.body"; } > "$OUT"
rm -f "$OUT.body" 2>/dev/null || true

# ---- 4. summary -----------------------------------------------------------
TP=$(awk -F'\t' '$5=="TRUE_POSITIVE"'  "$OUT" | wc -l | tr -d ' ')
RV=$(awk -F'\t' '$5=="review"'         "$OUT" | wc -l | tr -d ' ')
FP=$(awk -F'\t' '$5=="false_positive"' "$OUT" | wc -l | tr -d ' ')

echo
echo "==================== TRIAGE SUMMARY ===================="
printf "  TRUE_POSITIVE : %s\n  review        : %s\n  false_positive: %s\n" "$TP" "$RV" "$FP"
echo "  full results  : $OUT"
echo "======================================================="
if [[ "$TP" -gt 0 ]]; then
  echo
  echo "[+] TRUE POSITIVES (score / len / ctype / url):"
  awk -F'\t' '$5=="TRUE_POSITIVE"{printf "  %-4s %-9s %-22s %s\n",$1,$3,$4,$6}' "$OUT"
fi
