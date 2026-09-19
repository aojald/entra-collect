#!/usr/bin/env bash
# Launch a browser with CDP enabled so `collect.js --cdp` can attach to a real
# portal session (Authenticator QR / passkey included).
#
# Works on macOS and Linux. Windows: use login-edge.cmd.
#
# Two constraints drive the odd bits below:
#   1) macOS needs `open -a` for Bluetooth, otherwise hybrid passkey QR fails
#   2) Chrome/Edge 136+ ignore --remote-debugging-port on the DEFAULT profile,
#      so a dedicated user-data-dir is mandatory
#
# Usage: ./login-browser.sh [port] [url] [msedge|brave|chrome]
set -euo pipefail

PORT="${1:-9222}"
URL="${2:-https://entra.microsoft.com}"
WANTED="${3:-auto}"

# Session cookies for the target tenant live here — keep them out of the repo.
if [[ -n "${ENTRA_COLLECT_PROFILE_DIR:-}" ]]; then
  PROFILE_ROOT="$ENTRA_COLLECT_PROFILE_DIR"
elif [[ "$OSTYPE" == darwin* ]]; then
  PROFILE_ROOT="$HOME/Library/Application Support/entra-collect/profiles"
else
  PROFILE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/entra-collect/profiles"
fi

# No --remote-allow-origins: Playwright attaches without an Origin header, and
# the flag would let any web page talk to the debugging socket of an admin
# session for the whole run.
COMMON_ARGS=(
  --remote-debugging-port="${PORT}"
  --no-first-run
  --no-default-browser-check
  --enable-features=WebAuthenticationHybridTransports,WebAuthnHybridLinking,WebAuthnSecurityKeyAndQrCodeUiRefresh
)

cdp_up() {
  if command -v curl >/dev/null 2>&1; then
    curl -sf "http://127.0.0.1:${PORT}/json/version" >/dev/null 2>&1
  else
    command -v wget >/dev/null 2>&1 &&
      wget -qO- "http://127.0.0.1:${PORT}/json/version" >/dev/null 2>&1
  fi
}

if cdp_up; then
  echo "CDP already listening on ${PORT} — you can run:"
  echo "  node collect.js --auth browser --cdp http://127.0.0.1:${PORT}"
  exit 0
fi

pick_browser() {
  local candidates=()
  if [[ "$OSTYPE" == darwin* ]]; then
    case "$WANTED" in
      auto)   candidates=("Microsoft Edge:msedge" "Brave Browser:brave" "Google Chrome:chrome") ;;
      msedge) candidates=("Microsoft Edge:msedge") ;;
      brave)  candidates=("Brave Browser:brave") ;;
      chrome) candidates=("Google Chrome:chrome") ;;
    esac
    for entry in "${candidates[@]}"; do
      local app="${entry%%:*}"
      if [[ -d "/Applications/${app}.app" ]]; then
        echo "${entry}"
        return 0
      fi
    done
  else
    case "$WANTED" in
      auto)   candidates=("microsoft-edge:msedge" "microsoft-edge-stable:msedge" "google-chrome:chrome" "google-chrome-stable:chrome" "brave-browser:brave" "chromium:chromium") ;;
      msedge) candidates=("microsoft-edge:msedge" "microsoft-edge-stable:msedge") ;;
      brave)  candidates=("brave-browser:brave" "brave:brave") ;;
      chrome) candidates=("google-chrome:chrome" "google-chrome-stable:chrome") ;;
    esac
    for entry in "${candidates[@]}"; do
      local bin="${entry%%:*}"
      if command -v "$bin" >/dev/null 2>&1; then
        echo "${entry}"
        return 0
      fi
    done
  fi
  return 1
}

if ! SELECTED="$(pick_browser)"; then
  echo "No supported browser found (Edge / Brave / Chrome)."
  echo "Install one, or pass it explicitly: ./login-browser.sh ${PORT} '${URL}' msedge"
  exit 1
fi

BROWSER_ID="${SELECTED##*:}"
BROWSER_NAME="${SELECTED%%:*}"
PROFILE="${PROFILE_ROOT}/${BROWSER_ID}-cdp"
mkdir -p "${PROFILE}"

echo "Browser: ${BROWSER_NAME}"
echo "Profile: ${PROFILE}   (dedicated — sign in again here)"
echo "CDP:     http://127.0.0.1:${PORT}"
echo ""

if [[ "$OSTYPE" == darwin* ]]; then
  # `open -a` keeps the Info.plist Bluetooth entitlement, which the hybrid
  # passkey QR flow needs; launching the binary directly breaks it.
  open -na "${BROWSER_NAME}" --args \
    "${COMMON_ARGS[@]}" \
    --user-data-dir="${PROFILE}" \
    --disable-features=WebAuthenticationICloudKeychainForGoogle,WebAuthenticationICloudKeychainForActiveWithDrive,WebAuthenticationICloudKeychainForActiveWithoutDrive,WebAuthenticationICloudKeychainForInactiveWithDrive,WebAuthenticationICloudKeychainForInactiveWithoutDrive \
    "${URL}"
else
  nohup "${BROWSER_NAME}" \
    "${COMMON_ARGS[@]}" \
    --user-data-dir="${PROFILE}" \
    "${URL}" >/dev/null 2>&1 &
  disown || true
fi

printf "Waiting for CDP on port %s" "${PORT}"
for _ in $(seq 1 60); do
  if cdp_up; then
    echo " — OK"
    echo ""
    echo "Entra Collect — CDP ready. Sign in in that window, then:"
    echo "  node collect.js --auth browser --cdp http://127.0.0.1:${PORT}"
    echo "  Help: node collect.js --help"
    exit 0
  fi
  printf "."
  sleep 0.5
done

echo ""
echo "ERROR: CDP not listening after 30s."
echo "  Check <browser>://version for --remote-debugging-port"
echo "  A browser already running with the DEFAULT profile will ignore the flag."
exit 1
