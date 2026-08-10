#!/usr/bin/env bash
#
# debuglog_hunt.sh  --  one-shot pipeline (single target OR URL list)
# ---------------------------------------------------------------------------
# 1. Prompts for (or accepts) a target URL / URL list, and a wordlist.
# 2. Runs ffuf against URL/FUZZ with your exact flags — once per target.
# 3. Hands each ffuf JSON to parse_ffuf_debuglogs.sh (the verifier) which
#    triages hits into TRUE_POSITIVE / review / false_positive.
# 4. With a URL list, aggregates every target's TRUE_POSITIVES into one report.
#
# Usage (interactive):
#   ./debuglog_hunt.sh
#
# Single target:
#   ./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt
#
# Many targets (one URL per line in urls.txt; blank lines / # comments ok):
#   ./debuglog_hunt.sh -U urls.txt -w debug_logs_wordlist.txt
#
# Options:
#   -u URL        single target base URL (script appends /FUZZ)
#   -U FILE       file of target URLs, one per line (overrides -u)
#   -w WORDLIST   path to wordlist
#   -o DIR        run/output directory        (default: ./hunt_<timestamp>)
#   -r RATE       ffuf --rate                  (default: 50)
#   -t THREADS    ffuf -t                      (default: 100)
#   -m CODES      ffuf -mc match codes         (default: 200)
#   -c CONC       verifier concurrency         (default: 40)
#   -s SCORE      verifier true-positive score (default: 3)
#   -k            insecure TLS (passed to ffuf AND verifier)
#   -H 'H: V'     extra header (repeatable; passed to ffuf and verifier)
#   -F 'flags'    extra raw ffuf flags (e.g. '-ac -fc 404')
#   -h            help
# ---------------------------------------------------------------------------
set -euo pipefail

# --- locate the verifier (same dir as this script by default) --------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
VERIFIER="${VERIFIER:-$SCRIPT_DIR/parse_ffuf_debuglogs.sh}"

# --- defaults --------------------------------------------------------------
URL=""; URLLIST=""; WORDLIST=""; OUTDIR=""; RATE=50; THREADS=100; MC=200
VCONC=40; VSCORE=3; INSECURE=""; EXTRA_HEADERS=(); FFUF_EXTRA=""

usage(){ sed -n '2,40p' "$0"; exit "${1:-0}"; }

while getopts ":u:U:w:o:r:t:m:c:s:kH:F:h" opt; do
  case "$opt" in
    u) URL=$OPTARG ;;
    U) URLLIST=$OPTARG ;;
    w) WORDLIST=$OPTARG ;;
    o) OUTDIR=$OPTARG ;;
    r) RATE=$OPTARG ;;
    t) THREADS=$OPTARG ;;
    m) MC=$OPTARG ;;
    c) VCONC=$OPTARG ;;
    s) VSCORE=$OPTARG ;;
    k) INSECURE="-k" ;;
    H) EXTRA_HEADERS+=("$OPTARG") ;;
    F) FFUF_EXTRA=$OPTARG ;;
    h) usage 0 ;;
    :) echo "Missing arg for -$OPTARG" >&2; usage 1 ;;
    *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
  esac
done

# --- interactive prompts if nothing supplied -------------------------------
if [[ -z "$URL" && -z "$URLLIST" ]]; then
  read -r -p "Target URL, or path to a URL list file: " ANS
  if [[ -f "$ANS" ]]; then URLLIST="$ANS"; else URL="$ANS"; fi
fi
if [[ -z "$WORDLIST" ]]; then
  read -r -e -p "Wordlist path [$SCRIPT_DIR/debug_logs_wordlist.txt]: " WORDLIST
  WORDLIST="${WORDLIST:-$SCRIPT_DIR/debug_logs_wordlist.txt}"
fi

# --- validate --------------------------------------------------------------
[[ -r "$WORDLIST" ]] || { echo "[-] wordlist not readable: $WORDLIST" >&2; exit 1; }
command -v "${FFUF:-ffuf}" >/dev/null 2>&1 || { echo "[-] ffuf not found in PATH (set FFUF=/path/to/ffuf)" >&2; exit 1; }
[[ -x "$VERIFIER" || -r "$VERIFIER" ]] || { echo "[-] verifier not found: $VERIFIER" >&2; exit 1; }
FFUF_BIN="${FFUF:-ffuf}"

# --- build the target list (from -U file, else single -u) ------------------
TARGETS=()
if [[ -n "$URLLIST" ]]; then
  [[ -r "$URLLIST" ]] || { echo "[-] URL list not readable: $URLLIST" >&2; exit 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="$(echo -n "$line" | tr -d '\r' | xargs || true)"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^https?:// ]] || { echo "[!] skipping (no http/https): $line" >&2; continue; }
    TARGETS+=("${line%/}")
  done < "$URLLIST"
else
  [[ -n "$URL" ]] || { echo "[-] a target URL or -U list is required" >&2; exit 1; }
  [[ "$URL" =~ ^https?:// ]] || { echo "[-] URL must start with http:// or https://" >&2; exit 1; }
  TARGETS+=("${URL%/}")
fi
[[ "${#TARGETS[@]}" -gt 0 ]] || { echo "[-] no valid targets" >&2; exit 1; }

OUTDIR="${OUTDIR:-./hunt_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"
AGG_TSV="$OUTDIR/all_true_positives.tsv"
printf 'score\tstatus\tlength\tcontent-type\tverdict\turl\treasons\n' > "$AGG_TSV"

# --- assemble header flags for both tools ----------------------------------
FFUF_HDR=(); VERIFY_HDR=()
for h in "${EXTRA_HEADERS[@]:-}"; do
  [[ -z "$h" ]] && continue
  FFUF_HDR+=("-H" "$h"); VERIFY_HDR+=("-H" "$h")
done

echo "==========================================================="
echo " targets   : ${#TARGETS[@]}"
echo " wordlist  : $WORDLIST  ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
echo " outdir    : $OUTDIR"
echo " verifier  : $VERIFIER"
echo "==========================================================="

# --- helper: turn a URL into a filesystem-safe slug ------------------------
slug(){ echo -n "$1" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]#_#g' | cut -c1-80; }

# --- run one target through both stages ------------------------------------
GRAND_TP=0; IDX=0
run_one(){
  local base="$1" sub="$2"
  local fjson="$sub/ffuf_out.json" vtsv="$sub/debuglog_results.tsv"
  mkdir -p "$sub"

  echo; echo "[*] [$IDX/${#TARGETS[@]}] $base/FUZZ"
  echo "    STAGE 1 — ffuf ..."
  if ! "$FFUF_BIN" -w "$WORDLIST":FUZZ -u "$base/FUZZ" \
        -mc "$MC" -c -rate "$RATE" -t "$THREADS" \
        ${INSECURE:+-k} "${FFUF_HDR[@]}" $FFUF_EXTRA \
        -of json -o "$fjson" ; then
    echo "    [!] ffuf failed for $base — skipping"; return 0
  fi
  [[ -s "$fjson" ]] || { echo "    [!] no ffuf output for $base"; return 0; }

  local hits
  hits=$(grep -o '"url"' "$fjson" | wc -l | tr -d ' ')
  echo "    ffuf hits: $hits"
  [[ "$hits" -eq 0 ]] && { echo "    (nothing to verify)"; return 0; }

  echo "    STAGE 2 — verifier ..."
  bash "$VERIFIER" -i "$fjson" -o "$vtsv" \
       -c "$VCONC" -s "$VSCORE" ${INSECURE:+-k} "${VERIFY_HDR[@]}" \
       | sed 's/^/      /'

  # aggregate this target's true positives
  if [[ -f "$vtsv" ]]; then
    local tp
    tp=$(awk -F'\t' 'NR>1 && $5=="TRUE_POSITIVE"' "$vtsv" | tee -a "$AGG_TSV" | wc -l | tr -d ' ')
    GRAND_TP=$((GRAND_TP + tp))
  fi
}

for base in "${TARGETS[@]}"; do
  IDX=$((IDX+1))
  run_one "$base" "$OUTDIR/$(printf '%02d_' "$IDX")$(slug "$base")"
done

# de-dupe aggregate (keep header) and sort by score
if [[ $(wc -l < "$AGG_TSV") -gt 1 ]]; then
  { head -1 "$AGG_TSV"; tail -n +2 "$AGG_TSV" | sort -u | sort -t$'\t' -k1,1nr; } > "$AGG_TSV.s" \
    && mv "$AGG_TSV.s" "$AGG_TSV"
fi

echo
echo "================= PIPELINE COMPLETE ================="
echo "  targets scanned      : ${#TARGETS[@]}"
echo "  total TRUE_POSITIVES : $GRAND_TP"
echo "  per-target reports   : $OUTDIR/<NN>_<host>/debuglog_results.tsv"
echo "  combined TP report   : $AGG_TSV"
echo "===================================================="
if [[ "$GRAND_TP" -gt 0 ]]; then
  echo
  echo "[+] ALL TRUE POSITIVES (score / len / ctype / url):"
  awk -F'\t' 'NR>1{printf "  %-4s %-9s %-22s %s\n",$1,$3,$4,$6}' "$AGG_TSV"
fi
