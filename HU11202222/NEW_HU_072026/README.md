# NEW_HU_072026

Aplicação Python para executar backtests locais e somente leitura de regras de detecção de VPN sobre dados históricos no DB2. Gera relatórios em Markdown e JSON, sem realizar ações no LDAP ou alterações no banco.

## Funcionalidades

- Resume eventos e usuários no período analisado.
- Identifica usuários com excesso de IPs, hostnames ou dispositivos distintos.
- Detecta volume elevado de logins diários.
- Simula a política de VPN ativa com login em rede física.
- Valida tabelas e colunas antes das consultas.
- Reporta taxas de falso positivo e negativo como indisponíveis quando não há dados rotulados.

## Requisitos

- Python 3.9 ou superior.
- [`uv`](https://docs.astral.sh/uv/).
- Conectividade com o DB2.
- Arquivo `../gravar_dados_vpn/db2_credentials.json`:

```json
{
  "username": "...",
  "password": "..."
}
```

## Uso

```sh
cd backtest_vpn_local
cp .env.example .env
./run_backtest.sh --start 2026-06-01 --end 2026-07-01
```

Sem argumentos, o período padrão é de `2026-06-01` até `2026-07-01`. Os relatórios são gravados em `backtest_vpn_local/reports/`.

Consulte [`backtest_vpn_local/README.md`](backtest_vpn_local/README.md) para todas as opções de configuração e execução.

## Segurança

A aplicação realiza apenas consultas ao DB2 e não executa ações no LDAP. As credenciais são lidas exclusivamente de um arquivo JSON e não são incluídas nos relatórios.
