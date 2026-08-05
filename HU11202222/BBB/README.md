# Backtest VPN local

Aplicação Python local e somente leitura para executar casos preliminares de backtest de VPN no DB2 `B2DB2G5`.

Ela usa o arquivo de credenciais DB2 já existente em `../gravar_dados_vpn/db2_credentials.json` e não executa nenhuma ação real em LDAP, Redis ou ambiente produtivo. O resultado é gravado em `reports/` como JSON e Markdown.

## Instalação

```bash
cd /home/wsl/HU11202222/backtest_vpn_local
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Execução mínima

Informe o período e, se necessário, ajuste schema/tabela/colunas:

```bash
./run_backtest.sh \
  --start 2026-06-01 \
  --end 2026-07-01 \
  --schema DB2PEP \
  --table AUT_CPTV \
  --user-column CD_USU_AUT
```

## Política principal com login físico

Para simular a política `VPN ativa + login atual em rede física BB para a mesma chave`, informe a tabela histórica de logins físicos:

```bash
./run_backtest.sh \
  --start 2026-06-01 \
  --end 2026-07-01 \
  --physical-schema DB2PEP \
  --physical-table SUA_TABELA_LOGIN_FISICO \
  --physical-user-column CD_USU \
  --physical-timestamp-column TS_TRAN \
  --physical-network-column TIPO_REDE \
  --physical-network-value FISICA_BB
```

Se a tabela física não for informada, a regra fica documentada como `skipped` no relatório, e os casos preliminares sobre a base VPN continuam sendo executados.

## Casos preliminares implementados

| Caso | Objetivo |
| --- | --- |
| Volume histórico | Total de eventos e usuários analisados no período |
| VPN classificada | Quantidade de eventos da base VPN no período |
| Mais de N IPs por usuário | Detecta chaves com variação acima do limite em IP de origem ou IP corporativo |
| Mais de N hostnames por usuário | Detecta chaves com variação de hostname acima do limite |
| Mais de N dispositivos por usuário | Detecta chaves com variação de dispositivo acima do limite |
| Quantidade de logins por dia | Lista usuários/dias com volume acima do limite |
| VPN ativa + login físico | Simula elegibilidade para encerramento de sessão VPN, sem executar ação real |

Taxas de falso positivo/falso negativo dependem de massa validada. Nesta versão preliminar elas são reportadas como `not_available` quando não há base de validação configurada.
