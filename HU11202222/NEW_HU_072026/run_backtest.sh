#!/usr/bin/env bash
# run_backtest.sh — dispara o backtest label-free com log carimbado
# e mostra progresso em tempo real. Uso:
#   ./run_backtest.sh                       # janela padrão = últimos 33 dias
#   ./run_backtest.sh 30                    # janela = últimos 30 dias
#   ./run_backtest.sh "2026-06-20 00:00:00" "2026-07-23 00:00:00"
#
# Depois de rodar, publique o bundle em
#   acr_controle_acesso_dashboard/static/backtest_vpn/
# e faça bump em __version__ + values.yaml.

set -euo pipefail

REPO_LOCAL="/home/wsl/HU11202222/NEW_HU_072026/backtest_vpn_local"
CREDENTIALS="/home/wsl/HU11202222/gravar_dados_vpn/db2_credentials.json"
VENV_BIN="${REPO_LOCAL}/.venv/bin"
LOG_DIR="${REPO_LOCAL}/reports/logs"
mkdir -p "${LOG_DIR}" "${REPO_LOCAL}/reports/html"

if [[ $# -eq 2 ]]; then
    START="$1"
    END="$2"
elif [[ $# -eq 1 ]]; then
    DAYS="$1"
    END="$(date '+%Y-%m-%d 00:00:00')"
    START="$(date -d "${DAYS} days ago" '+%Y-%m-%d 00:00:00')"
else
    END="$(date '+%Y-%m-%d 00:00:00')"
    START="$(date -d '33 days ago' '+%Y-%m-%d 00:00:00')"
fi

STAMP="$(date '+%Y%m%d_%H%M%S')"
LOG="${LOG_DIR}/backtest_${STAMP}.log"

echo "== backtest label-free =="
echo "janela : ${START}  →  ${END}"
echo "log    : ${LOG}"
echo "início : $(date '+%Y-%m-%d %H:%M:%S')"
echo
echo "Acompanhe com:  tail -f ${LOG}"
echo

# Cada linha do stdout é prefixada com [HH:MM:SS elapsed=Ns]
START_EPOCH=$(date +%s)
stamp_prefix() {
    awk -v s="${START_EPOCH}" '{ now=systime(); printf("[%s elapsed=%ds] %s\n", strftime("%H:%M:%S", now), now - s, $0); fflush(); }'
}

MTA_CHUNK_HOURS=2 PYTHONUNBUFFERED=1 "${VENV_BIN}/backtest-vpn" labelfree \
    --start "${START}" --end "${END}" \
    --credentials-file "${CREDENTIALS}" \
    --mta-schema DB2PEP --mta-table MTA_AUT_CLI_TRAN \
    --mta-delta-minutes 10 --mta-max-users 100 --mta-users-per-batch 4 --mta-chunk-hours 2 \
    --active-window-hours 8 --distinct-limit 2 --daily-login-limit 10 \
    --output-dir "${REPO_LOCAL}/reports" --no-pseudonymize 2>&1 \
    | stamp_prefix | tee "${LOG}"

BUNDLE="$(ls -t ${REPO_LOCAL}/reports/results_bundle_*.json | head -1)"
echo
echo "bundle gerado: ${BUNDLE}"
echo "gerando HTM..."

"${VENV_BIN}/backtest-vpn" report-html \
    --bundle "${BUNDLE}" \
    --out-dir "${REPO_LOCAL}/reports/html" 2>&1 | stamp_prefix | tee -a "${LOG}"

echo
echo "== concluído em $(date '+%Y-%m-%d %H:%M:%S') =="
echo "bundle : ${BUNDLE}"
echo "log    : ${LOG}"
