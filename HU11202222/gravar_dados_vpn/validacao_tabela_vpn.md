# Guia de validação da tabela VPN no DB2

Este guia mostra como validar se o conteúdo de `tabela_vpn.md` está fiel à estrutura real da tabela no DB2 usando o script `explorar_tabela_vpn.py`.

## 1) Pré-requisitos

- Python 3.9+
- Acesso de rede ao host DB2
- Permissão de leitura no schema/tabela
- Pacote Python:

```bash
python3 -m pip install --user ibm_db
```

Se o ambiente exigir, instale também dependências de build (Linux), conforme política do servidor.

## 2) Criar arquivo de credenciais (seguro)

Crie um arquivo local `db2_credentials.json` no mesmo diretório do script:

```json
{
  "username": "SEU_USUARIO_DB2",
  "password": "SUA_SENHA_DB2"
}
```

Ajuste permissão para restringir leitura:

```bash
chmod 600 db2_credentials.json
```

Recomendação: não versionar esse arquivo no Git.

## 3) Descobrir schema e nome físico da tabela

O Markdown traz o nome lógico. Para validar no banco, você precisa do nome físico real da tabela e o schema.

Se você já souber, pule para a etapa 4.

Se não souber, rode consultas de descoberta (exemplo, com sua ferramenta SQL corporativa):

```sql
SELECT TABSCHEMA, TABNAME
FROM SYSCAT.TABLES
WHERE UPPER(TABNAME) LIKE '%VPN%'
ORDER BY TABSCHEMA, TABNAME;
```

## 4) Executar o script de inspeção

Exemplo de execução:

```bash
python3 explorar_tabela_vpn.py \
  --jdbc-url "jdbc:db2://brdb2p1.plexbsb.bb.com.br:446/BRDB2P1" \
  --schema "SEU_SCHEMA" \
  --table "SUA_TABELA" \
  --credentials-file "./db2_credentials.json" \
  --markdown "./tabela_vpn.md"
```

## 5) O que o script valida

1. Existência e metadados da tabela em `SYSCAT.TABLES`
2. Colunas reais em `SYSCAT.COLUMNS` (nome, tipo, tamanho, nulidade, etc.)
3. Chave primária em `SYSCAT.TABCONST` + `SYSCAT.KEYCOLUSE`
4. Índices em `SYSCAT.INDEXES`
5. Comparação automática das colunas físicas do Markdown versus DB2
6. Contagem de linhas e amostra de dados (top 5)

Observação de compatibilidade DB2:
- O script detecta automaticamente se o catálogo disponível é `SYSCAT` (comum em DB2 LUW) ou `SYSIBM` (comum em DB2 z/OS).
- Isso evita o erro `SQL0204N "SYSCAT.TABLES" is an undefined name`.

## 6) Interpretação rápida do resultado

- Mensagem `OK: As colunas fisicas do Markdown batem com o DB2.`
  - O conjunto de colunas físicas está consistente
- Se aparecerem colunas "presentes no Markdown e ausentes no DB2"
  - O documento está desatualizado ou usa nome diferente
- Se aparecerem colunas "presentes no DB2 e ausentes no Markdown"
  - O documento está incompleto

## 7) Próximo passo recomendado

Depois da validação de colunas, faça uma segunda rodada para validar:

- tipo de dado exato (`char`, `decimal`, `timestamp`, etc.)
- tamanho/escala (`LENGTH`, `SCALE`)
- nulidade (`NULLS`)
- constraints e índices relevantes para performance e governança

Se quiser, posso criar uma versão 2 do script que também compara automaticamente datatype/nullabilidade do `.md` com o banco.
