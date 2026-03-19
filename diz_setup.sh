#!/usr/bin/env bash
# =============================================================================
# Dijital İz Sürücü — ortam kurulumu (Linux / macOS)
# Tek komutla bağımlılık + Sigma + Chainsaw mapping: Velociraptor’un “tek binary,
# tam yetenek” felsefesine paralel olarak, kullanıcı tek script ile üretim ortamını
# ayağa kaldırır; sahada dağıtılan araçlar (PATH’teki Hayabusa/Chainsaw vb.) aynı
# arayüzden beslenir.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  DİZ SETUP — pip + rules/sigma + mappings                            ║"
echo "║  (Velociraptor tarzı: tek giriş noktası, minimum sürtünme)              ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

if command -v python3 >/dev/null 2>&1; then
  PY=(python3)
elif command -v python >/dev/null 2>&1; then
  PY=(python)
else
  echo "[!] Python bulunamadı. python3 veya python kurun." >&2
  exit 1
fi

echo "[*] pip: requirements.txt kuruluyor..."
"${PY[@]}" -m pip install --upgrade pip >/dev/null 2>&1 || true
"${PY[@]}" -m pip install -r "${ROOT}/requirements.txt"

mkdir -p "${ROOT}/rules" "${ROOT}/mappings"

# --- Sigma kuralları (Chainsaw / DİZ sigma yolu) ---
SIGMA_DIR="${ROOT}/rules/sigma"
need_sigma=false
if [[ ! -d "${SIGMA_DIR}" ]]; then
  need_sigma=true
elif [[ -z "$(find "${SIGMA_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null | head -1)" ]]; then
  need_sigma=true
fi

if [[ "${need_sigma}" == true ]]; then
  echo "[*] rules/sigma eksik veya boş — git clone: SigmaHQ/sigma"
  rm -rf "${SIGMA_DIR}"
  if ! command -v git >/dev/null 2>&1; then
    echo "[!] git bulunamadı. Git kurun veya rules/sigma klasörünü manuel doldurun." >&2
    exit 1
  fi
  git clone --depth 1 "https://github.com/SigmaHQ/sigma" "${SIGMA_DIR}"
  echo "[+] Sigma kuralları: ${SIGMA_DIR}"
else
  echo "[+] rules/sigma mevcut: ${SIGMA_DIR}"
fi

# --- Chainsaw mappings (WithSecureLabs/chainsaw) — git clone ile doldur ---
MAPPING_FILE="${ROOT}/mappings/sigma-event-logs-all.yml"
CHAINSAW_REPO="https://github.com/WithSecureLabs/chainsaw"

need_mappings=false
if [[ ! -f "${MAPPING_FILE}" ]]; then
  need_mappings=true
elif [[ -z "$(find "${ROOT}/mappings" -maxdepth 1 -name '*.yml' 2>/dev/null | head -1)" ]]; then
  need_mappings=true
fi

if [[ "${need_mappings}" == true ]]; then
  echo "[*] mappings eksik veya bos — git clone: ${CHAINSAW_REPO} (shallow), yml kopyalaniyor..."
  if ! command -v git >/dev/null 2>&1; then
    echo "[!] git bulunamadı (mappings için gerekli)." >&2
    exit 1
  fi
  TMP_CLONE="$(mktemp -d)"
  trap "rm -rf \"${TMP_CLONE}\"" EXIT
  git clone --depth 1 "${CHAINSAW_REPO}" "${TMP_CLONE}/chainsaw"
  mkdir -p "${ROOT}/mappings"
  cp "${TMP_CLONE}/chainsaw/mappings/"*.yml "${ROOT}/mappings/"
  rm -rf "${TMP_CLONE}"
  trap - EXIT
  echo "[+] mappings: ${ROOT}/mappings/"
else
  echo "[+] mappings mevcut: ${MAPPING_FILE}"
fi

echo ""
echo "[+] Kurulum tamam."
echo "    • DFIR binary’leri (Hayabusa, Chainsaw, Volatility, Zeek, tshark) PATH’te veya proje kökünde olmalı."
echo "    • Analiz (Windows): diz_run.bat  |  (Linux/macOS): python main.py --input <klasör> ..."
echo ""
