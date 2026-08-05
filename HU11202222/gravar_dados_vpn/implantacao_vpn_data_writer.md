# Guia de Implantação: vpn_data_writer.py

Script que lê sessões VPN do Redis (gravadas pelo `login_handler.py`) e insere na tabela `DB2PEP.AUT_CPTV`.

---

## Arquitetura

```
rsyslog → login_handler.py → Redis (sessions)
                                    ↓
                          vpn_data_writer.py (poll contínuo)
                                    ↓
                          DB2 → DB2PEP.AUT_CPTV
```

---

## 1) Pré-requisitos

| Item | Detalhe |
|------|---------|
| Python | 3.9+ |
| uv | Instalado (`curl -LsSf https://astral.sh/uv/install.sh \| sh`) |
| Pacotes | `ibm-db`, `redis`, `python-dotenv` (gerenciados pelo `uv` via inline metadata) |
| Rede | Acesso ao DB2 (`brdb2p1.plexbsb.bb.com.br:446`) e ao Redis Sentinel |
| Credenciais | Arquivo `db2_credentials.json` (já existente) |

### Instalar uv (se ainda não tiver)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

As dependências são declaradas no próprio script (PEP 723 inline metadata) e resolvidas automaticamente pelo `uv run`.

---

## 2) Configuração

### 2.1) Variáveis de ambiente

Crie ou edite o arquivo `.env` no mesmo diretório do script:

```env
# Redis Sentinel (mesmo do login_handler)
REDIS_SENTINELS=sentinel1:26379,sentinel2:26379,sentinel3:26379
REDIS_MASTER_NAME=mymaster
REDIS_SENTINEL_PASSWORD=sua_senha_sentinel
REDIS_MASTER_USERNAME=default
REDIS_PASSWORD=sua_senha_redis

# DB2
DB2_HOSTNAME=brdb2p1.plexbsb.bb.com.br
DB2_PORT=446
DB2_DATABASE=BRDB2P1
DB2_SCHEMA=DB2PEP
DB2_TABLE=AUT_CPTV
DB2_CREDENTIALS_FILE=./db2_credentials.json

# Operacional
POLL_INTERVAL_SECONDS=5
LOG_FILE=/var/log/vpn_data_writer.log
```

### 2.2) Arquivo de credenciais DB2

Já existente em `db2_credentials.json`:

```json
{
  "username": "DB2PEP01",
  "password": "SUA_SENHA"
}
```

Garanta permissão restrita:

```bash
chmod 600 db2_credentials.json
```

---

## 3) Mapeamento de campos (Redis → DB2)

| Campo Redis | Coluna DB2 | Tipo DB2 | Notas |
|-------------|-----------|----------|-------|
| *(gerado)* | CD_IDFR_AUT | decimal(11) | PK sequencial (MAX+1) |
| session_uid | CD_UNCO_AUT | char(43) | UUID da sessão |
| login_timestamp / time | TS_TRAN | timestamp | Obrigatório |
| *(derivado do mês)* | NR_PTC | smallint | Partição mensal |
| src | CD_END_LGC_OGM | char(15) | IP de origem |
| office_mode_ip | CD_END_LGC_CPTV | char(15) | IP corporativo |
| auth_method | NM_MTD_AUT | char(30) | Método de autenticação |
| device_name | NM_DSVO | char(50) | Hostname do dispositivo |
| mac_address | CD_END_FSCO | char(22) | MAC address |
| device_id | CD_IDFC_DSVO | char(40) | ID do dispositivo |
| fingerprint | CD_IDFC_ACSS | char(60) | Hash do certificado |
| os_name | NM_SO | char(20) | Sistema operacional |
| os_version | CD_VRS_SO | char(10) | Versão do SO |
| connection_type | CD_TIP_CNXO | char(10) | IPSec ou SSL |
| matricula_id | CD_USU_AUT | char(8) | Matrícula do funcionário |
| access_group | TX_GR_ACSS | char(254) | Grupo de acesso |

---

## 4) Implantação como serviço (rsyslog)

Semelhante ao `login_handler.py`, registre o script como programa executado pelo rsyslog.

### Opção A: rsyslog (omprog)

Edite `/etc/rsyslog.d/vpn_db2.conf`:

```
module(load="omprog")

# Este script não precisa de input do rsyslog.
# Para execução contínua via rsyslog, use um timer/cron ou systemd.
```

> **Nota:** Como o `vpn_data_writer.py` **não lê stdin** (diferente do login_handler), a forma ideal de mantê-lo rodando é via **systemd**.

### Opção B: systemd (recomendado)

Crie `/etc/systemd/system/vpn-data-writer.service`:

```ini
[Unit]
Description=VPN Data Writer - Redis to DB2
After=network.target redis.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/root/.local/bin/uv run /usr/local/bin/vpn_data_writer.py
Restart=always
RestartSec=10
EnvironmentFile=/usr/local/bin/.env

[Install]
WantedBy=multi-user.target
```

### Ativar o serviço

```bash
# Copiar script
sudo cp vpn_data_writer.py /usr/local/bin/
sudo cp db2_credentials.json /usr/local/bin/
sudo cp .env /usr/local/bin/.env
sudo chmod 600 /usr/local/bin/db2_credentials.json /usr/local/bin/.env

# Habilitar e iniciar
sudo systemctl daemon-reload
sudo systemctl enable vpn-data-writer.service
sudo systemctl start vpn-data-writer.service

# Verificar status
sudo systemctl status vpn-data-writer.service
sudo journalctl -u vpn-data-writer.service -f
```

---

## 5) Monitoramento e logs

```bash
# Log principal
tail -f /var/log/vpn_data_writer.log

# Status do serviço
systemctl status vpn-data-writer.service

# Verificar registros gravados no DB2
python3 explorar_tabela_vpn.py \
  --jdbc-url "jdbc:db2://brdb2p1.plexbsb.bb.com.br:446/BRDB2P1" \
  --schema "DB2PEP" \
  --table "AUT_CPTV" \
  --credentials-file "./db2_credentials.json" \
  --markdown "./tabela_vpn.md"
```

---

## 6) Controle de duplicação

O script mantém duas estruturas no Redis para evitar duplicação:

| Chave Redis | Função |
|-------------|--------|
| `PEP:db2writer:last_score` | Cursor do último score processado no ZSET |
| `PEP:db2writer:written` | SET com session_uids já gravados no DB2 |

Se precisar **reprocessar** tudo (ex: tabela foi truncada):

```bash
redis-cli DEL PEP:db2writer:last_score PEP:db2writer:written
```

---

## 7) Troubleshooting

| Problema | Solução |
|----------|---------|
| `ibm_db` não instala | Instale o IBM DB2 CLI driver: `export IBM_DB_HOME=/opt/ibm/db2cli` |
| Conexão DB2 recusada | Verifique firewall/rede para `brdb2p1.plexbsb.bb.com.br:446` |
| Sessões não aparecem no DB2 | Verifique se `login_handler.py` está gravando no Redis |
| Erro de PK duplicada | O cursor Redis pode ter sido resetado — verifique `PEP:db2writer:written` |
| Timeout Redis | Ajuste `REDIS_SENTINELS` e verifique conectividade |

---

## 8) Teste manual rápido

```bash
# Rodar em foreground para debug
cd /home/wsl/gravar_dados_vpn
uv run vpn_data_writer.py
```

Na primeira execução, `uv` criará automaticamente o venv e instalará `ibm-db`, `redis` e `python-dotenv`.

Logs aparecerão em `/var/log/vpn_data_writer.log` (ou stdout se o arquivo não for gravável).
