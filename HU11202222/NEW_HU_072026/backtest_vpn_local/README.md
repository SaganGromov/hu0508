# backtest-vpn-local

Backtest local, 100% somente leitura, das regras de deteccao de VPN sobre
dados historicos na tabela `DB2PEP.AUT_CPTV` (DB2). O objetivo e medir a
efetividade das regras atuais e apoiar decisoes do time de risco / prevencao
a fraudes, sem nenhuma acao em producao, LDAP ou dados sensiveis em tempo
real. A saida sao dois relatorios (Markdown legivel para publico nao tecnico
e JSON com amostras detalhadas).

## Pre-requisitos

- `uv` instalado (ver Instalacao).
- Arquivo de credenciais do DB2 em `../gravar_dados_vpn/db2_credentials.json`
  (JSON com as chaves `username` e `password`), preferencialmente com
  `chmod 600`.
- Conectividade de rede com `b2db2g5.plexbs2.bb.com.br:61250` (DB2 B2DB2G5).

Este diretorio (`backtest_vpn_local/`) deve ficar como irmao do diretorio
`gravar_dados_vpn/` ja existente, para que o caminho padrao das credenciais
funcione sem configuracao extra.

## Instalacao

Instale o `uv` (uma unica vez):

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Nao ha `pip`, `requirements.txt` nem criacao manual de venv: o
`run_backtest.sh` usa `uv run`, que resolve a dependencia (`ibm-db>=3.2.0`)
a partir do `pyproject.toml`.

## Execucao minima

```sh
./run_backtest.sh --start 2026-06-01 --end 2026-07-01 \
    --schema DB2PEP --table AUT_CPTV --user-column CD_USU_AUT
```

Sem argumentos, o script usa `--start 2026-06-01 --end 2026-07-01`. O script
pode ser chamado de qualquer diretorio (ele resolve o proprio caminho).
Os relatorios sao gravados em `reports/` (ajustavel com `--output-dir`).

## Politica principal com login em rede fisica

A politica da HU ("existe sessao ativa para a mesma chave com VPN + login
atual em rede fisica do BB = encerra sessao de VPN no LDAP") e apenas
SIMULADA em elegibilidade; nenhuma chamada ao LDAP e feita. Ela exige a
configuracao de uma tabela de logins em rede fisica:

```sh
./run_backtest.sh --start 2026-06-01 --end 2026-07-01 \
    --schema DB2PEP --table AUT_CPTV --user-column CD_USU_AUT \
    --physical-schema DB2PEP \
    --physical-table LOGINS_REDE_FISICA \
    --physical-user-column CD_USU_AUT \
    --physical-timestamp-column TS_TRAN \
    --physical-network-column CD_TIP_REDE \
    --physical-network-value FISICA \
    --active-window-hours 8
```

Sem `--physical-table` (ou `PHYSICAL_TABLE`), esse caso e reportado com
status `skipped` e todos os demais casos executam normalmente.
`--physical-network-column` e `--physical-network-value` sao opcionais, mas
devem ser informados juntos.

Todas as flags tambem podem vir de variaveis de ambiente (ver
`.env.example`); a flag de CLI sempre vence.

## Casos preliminares implementados

| Caso | Descricao | Parametro |
| --- | --- | --- |
| Resumo do periodo | Total de eventos e usuarios distintos no periodo | `--start` / `--end` |
| ips_distintos_acima_do_limite | Usuarios com mais de N IPs distintos (origem ou corporativo) | `--distinct-limit` (padrao 2) |
| hostnames_distintos_acima_do_limite | Usuarios com mais de N hostnames distintos | `--distinct-limit` |
| dispositivos_distintos_acima_do_limite | Usuarios com mais de N IDs de dispositivo distintos | `--distinct-limit` |
| logins_diarios_acima_do_limite | Usuarios com mais de K logins no mesmo dia | `--daily-login-limit` (padrao 10) |
| vpn_ativa_com_login_em_rede_fisica | Simulacao de elegibilidade da politica principal (VPN ativa + login fisico na janela) | `--physical-*` e `--active-window-hours` (padrao 8) |

## Taxas de falso positivo / falso negativo

As taxas de FP/FN so ficam disponiveis quando houver uma base rotulada e
validada. Enquanto isso, o relatorio informa
`not_available_without_validated_labels` nesses campos — o app nao inventa
rotulos.

## Seguranca

- Execucao somente leitura: nenhum INSERT/UPDATE/DELETE no DB2.
- Nenhuma acao no LDAP; apenas simulacao de elegibilidade.
- Nenhum dado sensivel em tempo real; apenas base historica.
- Credenciais somente pelo arquivo JSON (`db2_credentials.json`, com
  `chmod 600`). Nunca passe senha por CLI, variavel de ambiente ou `.env`,
  e nada de senha aparece em logs ou relatorios.
