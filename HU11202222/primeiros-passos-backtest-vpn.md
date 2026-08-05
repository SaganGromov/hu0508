# Primeiros passos - Backtest de VPN

## 1. Contexto da história de usuário

A história tem como objetivo criar um backtest para simular e validar casos de VPN identificados por modelos e regras atuais de prevenção a fraudes.

O backtest deve permitir avaliar a efetividade dos critérios existentes, identificar falsos positivos e falsos negativos quando aplicável, além de apoiar decisões de melhoria nos controles de segurança.

## 2. Objetivo inicial

Antes de implementar a rotina do backtest, os primeiros passos devem garantir que o time tenha clareza sobre:

- quais bases históricas serão usadas;
- quais regras de VPN serão simuladas;
- quais métricas serão calculadas;
- quais premissas e limitações precisam ser documentadas;
- como o resultado será apresentado para o time e stakeholders.

## 3. Passo 1 - Alinhar entendimento funcional da HU

O primeiro passo é realizar um alinhamento funcional com as pessoas envolvidas, especialmente analistas de risco, prevenção a fraudes, time técnico e responsáveis pelas regras atuais.

### Pontos a esclarecer

- O que será considerado um caso de VPN no backtest.
- Quais modelos e regras atuais devem entrar na primeira versão.
- Se a análise será feita por login, sessão, chave de usuário, IP, hostname ou combinação desses elementos.
- Se haverá uma janela de tempo padrão para análise.
- Quais situações serão consideradas falso positivo e falso negativo.
- Quais stakeholders irão consumir o resultado final.

### Resultado esperado

Ao final desse alinhamento, deve existir uma definição comum sobre o escopo inicial do backtest e sobre o que significa sucesso para essa primeira entrega.

## 4. Passo 2 - Conhecer a implementação atual com o Theo do SGN

A HU indica a necessidade de conhecer a implementação existente com o Theo do SGN. Esse passo é essencial para evitar duplicidade de esforço e garantir que o backtest siga a lógica já usada atualmente.

### Pontos a levantar

- Como as sessões de VPN são identificadas hoje.
- Quais fontes de dados são usadas pela implementação atual.
- Onde estão as regras, modelos ou consultas que identificam os casos.
- Quais campos são obrigatórios para aplicar as regras.
- Se existem tratamentos específicos para IP, hostname, dispositivo ou chave de usuário.
- Se há histórico de problemas conhecidos, exceções ou limitações.

### Resultado esperado

Um resumo técnico-funcional da implementação atual, contendo as regras existentes, fontes de dados utilizadas e eventuais restrições para simulação histórica.

## 5. Passo 3 - Definir o primeiro caso de política VPN

Como primeiro recorte, a HU destaca a seguinte política:

> Existe sessão ativa para a mesma chave com VPN + login atual em rede física do BB = encerra sessão de VPN no LDAP.

Esse caso deve ser priorizado para reduzir o escopo inicial e permitir uma primeira validação objetiva do backtest.

### Detalhamento necessário

- Identificar como reconhecer uma sessão ativa de VPN.
- Identificar como reconhecer um login em rede física do BB.
- Confirmar se a comparação deve ser feita pela mesma chave de usuário.
- Definir a janela de tempo em que uma sessão será considerada ativa.
- Definir o comportamento esperado no backtest: apenas simular o encerramento ou também classificar o caso como ação recomendada.

### Resultado esperado

Uma regra formal documentada, com entrada, condição e saída esperada.

Exemplo:

| Item | Definição |
| --- | --- |
| Entrada | Histórico de sessões e logins por chave de usuário |
| Condição | Usuário possui sessão VPN ativa e realiza login em rede física do BB |
| Saída | Caso classificado como elegível para encerramento de sessão VPN no LDAP |
| Impacto real | Nenhum, pois o backtest não deve atuar em ambiente produtivo |

## 6. Passo 4 - Levantar e validar a base histórica

O backtest só será válido se a base histórica for representativa e previamente validada pelo time.

### Critérios para escolha da base

- Deve conter volume suficiente de acessos para análise.
- Deve possuir registros de VPN e rede física.
- Deve conter os campos necessários para aplicar as regras.
- Deve cobrir um período relevante para o negócio.
- Não deve expor dados sensíveis em tempo real.
- Deve permitir reexecução do backtest com os mesmos parâmetros.

### Campos mínimos recomendados

| Campo | Finalidade |
| --- | --- |
| Chave do usuário | Relacionar sessões e logins da mesma pessoa |
| Data e hora do evento | Avaliar ordem dos eventos e janelas de tempo |
| Tipo de rede | Distinguir VPN de rede física |
| IP | Identificar mudanças ou múltiplos IPs |
| Hostname | Apoiar identificação de origem/dispositivo |
| Dispositivo | Avaliar troca ou comportamento atípico |
| Status da sessão | Identificar sessão ativa, encerrada ou bloqueada |
| Origem do evento | Rastrear fonte do dado |

### Resultado esperado

Uma base histórica definida e validada, com período, origem, campos disponíveis e limitações conhecidas documentados.

## 7. Passo 5 - Definir parâmetros do backtest

Para garantir reprodutibilidade, todos os parâmetros usados no backtest devem ser documentados antes da execução.

### Parâmetros iniciais sugeridos

| Parâmetro | Exemplo de definição |
| --- | --- |
| Período analisado | Últimos 30, 60 ou 90 dias disponíveis |
| Unidade de análise | Evento de login ou sessão |
| Identificador principal | Chave do usuário |
| Janela de sessão ativa | Definir conforme regra atual ou implementação SGN |
| Tipo de rede VPN | Conforme classificação existente na base |
| Tipo de rede física BB | Conforme classificação existente na base |
| Regras aplicadas | Política priorizada de sessão VPN + login físico |
| Saída esperada | Tabela ou relatório consolidado |

### Resultado esperado

Um conjunto versionado de parâmetros que permita executar novamente o backtest e comparar resultados.

## 8. Passo 6 - Mapear regras futuras de detecção de anomalia

Embora o primeiro caso deva focar na política de VPN, a HU também menciona regras de anomalia que devem ser mapeadas para evolução posterior.

### Regras citadas na HU

- Acesso fora do horário padrão.
- Comparação com comportamento habitual.
- Mudanças de IP.
- Mudanças de dispositivo.
- Quantidade de logins por dia.
- Login durante férias.
- Mais de dois IPs por usuário.
- Mais de dois hostnames por usuário.

### Resultado esperado

Uma lista priorizada das regras, separando o que entra na primeira versão do backtest e o que ficará para evolução posterior.

## 9. Passo 7 - Definir métricas e formato dos resultados

Os critérios de aceite exigem que o resultado apresente, no mínimo:

- volume total de casos analisados;
- quantidade de casos classificados como VPN;
- taxa de falso positivo, quando aplicável;
- taxa de falso negativo, quando aplicável.

### Métricas iniciais recomendadas

| Métrica | Descrição |
| --- | --- |
| Total de eventos analisados | Quantidade total de registros processados |
| Total de usuários analisados | Quantidade de chaves únicas avaliadas |
| Casos com VPN identificada | Quantidade de registros ou sessões classificados como VPN |
| Casos elegíveis para ação | Quantidade de casos que atenderam à política priorizada |
| Falsos positivos | Casos classificados como risco, mas considerados válidos após validação |
| Falsos negativos | Casos não classificados pela regra, mas que deveriam ter sido identificados |

### Resultado esperado

Um modelo simples de saída, preferencialmente em tabela ou relatório, que seja compreensível para o time técnico e para stakeholders.

## 10. Passo 8 - Definir premissas, restrições e cuidados

Como o backtest trabalha com histórico de acessos, é necessário documentar limites e cuidados antes da execução.

### Premissas

- A base histórica foi validada pelo time responsável.
- As regras atuais de VPN estão disponíveis e compreendidas.
- O backtest será executado apenas em ambiente seguro e controlado.
- O processo não executará ações reais no LDAP ou em ambientes produtivos.

### Restrições

- A qualidade do resultado depende da qualidade da base histórica.
- Taxas de falso positivo e falso negativo dependem da existência de massa validada ou critério de comparação.
- Regras incompletas ou não documentadas podem limitar a reprodutibilidade.

### Cuidados

- Não usar dados sensíveis em tempo real.
- Evitar exposição desnecessária de dados pessoais.
- Registrar origem, período e filtros aplicados na base.
- Garantir que a execução seja apenas simulada.

## 11. Checklist para iniciar a implementação

Antes de desenvolver a rotina do backtest, confirmar:

- [ ] Escopo inicial validado com o time.
- [ ] Implementação atual conhecida com o Theo do SGN.
- [ ] Primeira política VPN documentada.
- [ ] Base histórica identificada e validada.
- [ ] Campos obrigatórios disponíveis na base.
- [ ] Parâmetros do backtest definidos.
- [ ] Métricas mínimas definidas.
- [ ] Formato do relatório definido.
- [ ] Premissas e limitações documentadas.
- [ ] Garantia de que não haverá impacto em produção.

## 12. Entregáveis esperados nessa fase inicial

Ao final dos primeiros passos, o time deve ter:

1. Documento de entendimento da regra atual de VPN.
2. Definição da base histórica a ser usada.
3. Lista de parâmetros do backtest.
4. Modelo inicial de saída dos resultados.
5. Checklist de segurança e não impacto produtivo.
6. Priorização das regras que entram na primeira versão.

## 13. Sugestão de quebra da história

Caso a base histórica ou as métricas ainda não estejam maduras, recomenda-se iniciar com uma SPIKE.

### SPIKE - Análise e definição

Objetivo: validar base histórica, entender implementação atual e fechar regras/métricas da primeira versão.

### Desenvolvimento - Backtest de VPN

Objetivo: implementar a rotina de execução do backtest, consolidar os resultados e disponibilizar relatório simples para análise.

