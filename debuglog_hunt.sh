#!/usr/bin/env bash
#
# debuglog_hunt.sh  --  one-shot pipeline
# ---------------------------------------------------------------------------
# 1. Prompts for (or accepts) a target URL and a wordlist.
# 2. Runs ffuf against URL/FUZZ with your exact flags.
# 3. Hands the ffuf JSON straight to parse_ffuf_debuglogs.sh (the verifier)
#    which triages hits into TRUE_POSITIVE / review / false_positive.
#
# Usage (interactive):
#   ./debuglog_hunt.sh
#
# Usage (non-interactive):
#   ./debuglog_hunt.sh -u https://target.com -w debug_logs_wordlist.txt
#
# Options:
#   -u URL        target base URL (no trailing /FUZZ; script adds it)
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
URL=""; WORDLIST=""; OUTDIR=""; RATE=50; THREADS=100; MC=200
VCONC=40; VSCORE=3; INSECURE=""; EXTRA_HEADERS=(); FFUF_EXTRA=""

usage(){ sed -n '2,40p' "$0"; exit "${1:-0}"; }

while getopts ":u:w:o:r:t:m:c:s:kH:F:h" opt; do
  case "$opt" in
    u) URL=$OPTARG ;;
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

# --- interactive prompts if not supplied -----------------------------------
if [[ -z "$URL" ]]; then
  read -r -p "Target URL (e.g. https://target.com): " URL
fi
if [[ -z "$WORDLIST" ]]; then
  read -r -e -p "Wordlist path [$SCRIPT_DIR/debug_logs_wordlist.txt]: " WORDLIST
  WORDLIST="${WORDLIST:-$SCRIPT_DIR/debug_logs_wordlist.txt}"
fi

# --- validate --------------------------------------------------------------
[[ -n "$URL" ]]      || { echo "[-] URL is required" >&2; exit 1; }
[[ "$URL" =~ ^https?:// ]] || { echo "[-] URL must start with http:// or https://" >&2; exit 1; }
[[ -r "$WORDLIST" ]] || { echo "[-] wordlist not readable: $WORDLIST" >&2; exit 1; }
command -v "${FFUF:-ffuf}" >/dev/null 2>&1 || { echo "[-] ffuf not found in PATH (set FFUF=/path/to/ffuf)" >&2; exit 1; }
[[ -x "$VERIFIER" || -r "$VERIFIER" ]] || { echo "[-] verifier not found: $VERIFIER" >&2; exit 1; }
FFUF_BIN="${FFUF:-ffuf}"

# normalise: strip a trailing slash so we build exactly URL/FUZZ
BASE="${URL%/}"
OUTDIR="${OUTDIR:-./hunt_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"
FFUF_JSON="$OUTDIR/ffuf_out.json"
VERIFY_TSV="$OUTDIR/debuglog_results.tsv"

# --- assemble header flags for both tools ----------------------------------
FFUF_HDR=(); VERIFY_HDR=()
for h in "${EXTRA_HEADERS[@]:-}"; do
  [[ -z "$h" ]] && continue
  FFUF_HDR+=("-H" "$h"); VERIFY_HDR+=("-H" "$h")
done

echo "==========================================================="
echo " target    : $BASE/FUZZ"
echo " wordlist  : $WORDLIST  ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
echo " ffuf out  : $FFUF_JSON"
echo " verifier  : $VERIFIER"
echo "==========================================================="

# --- STAGE 1: ffuf ---------------------------------------------------------
echo; echo "[*] STAGE 1 — running ffuf ..."
set -x
"$FFUF_BIN" -w "$WORDLIST":FUZZ -u "$BASE/FUZZ" \
      -mc "$MC" -c -rate "$RATE" -t "$THREADS" \
      ${INSECURE:+-k} "${FFUF_HDR[@]}" $FFUF_EXTRA \
      -of json -o "$FFUF_JSON"
set +x

# ffuf writes {"results":[]} even on no hits; make sure the file exists
[[ -s "$FFUF_JSON" ]] || { echo "[-] ffuf produced no output file"; exit 1; }

HITS=$(grep -o '"url"' "$FFUF_JSON" | wc -l | tr -d ' ')
echo "[*] ffuf finished — $HITS raw hit(s) recorded in $FFUF_JSON"
if [[ "$HITS" -eq 0 ]]; then
  echo "[!] no hits to verify. Tip: try -m all with -F '-ac -fc 404' for soft-404 sites."
  exit 0
fi

# --- STAGE 2: verifier -----------------------------------------------------
echo; echo "[*] STAGE 2 — verifying hits with $VERIFIER ..."
bash "$VERIFIER" -i "$FFUF_JSON" -o "$VERIFY_TSV" \
     -c "$VCONC" -s "$VSCORE" ${INSECURE:+-k} "${VERIFY_HDR[@]}"

echo
echo "[✓] pipeline complete."
echo "    raw ffuf hits : $FFUF_JSON"
echo "    triaged report: $VERIFY_TSV"
