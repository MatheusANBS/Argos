# ADR-0013 — Inspeção de endereço por evidência derivada

Status: aceito e implementado (referências por índice permanecem propostas)

## Contexto

Classificar um endereço encontrado por `scan_exact`, `scan_first` ou por uma
cadeia de ponteiros exige hoje combinar manualmente `memory_debug_regions`,
`memory_debug_modules`, várias leituras e um scan reverso. O cliente precisa
correlacionar proteções, calcular RVA, procurar um possível início de objeto
antes do campo e decidir se um qword/dword se parece com uma vtable. Esse fluxo
repete I/O, transfere bytes crus e incentiva conclusões fortes a partir de uma
heurística fraca.

A [ADR-0011](0011-reverse-pointer-chain-scan.md) já trata referências reversas
e cadeias como candidatos limitados, não como prova de tipo. A
[ADR-0012](0012-async-scan-progress-resumption.md), proposta, define progresso,
cobertura, retomada e motivos explícitos de término para scans. A
[ADR-0018](0018-persistent-pointer-index.md), proposta, e a
[Spec 0010](../specs/0010-persistent-pointer-index.md), proposta, definem um
índice de ponteiros reutilizável. Falta uma composição read-only que apresente
essas evidências de forma pequena, determinística e honesta.

## Decisão

Adicionar `memory_debug_inspect_address`. A tool recebe uma sessão autorizada,
um endereço e largura explícita de ponteiro (`4` ou `8`). Ela devolve:

- a região que contém o endereço e suas proteções;
- o módulo dono, quando houver, com `module + RVA` calculado com overflow
  verificado;
- zero ou mais candidatos rankeados de início de objeto/vtable;
- opcionalmente, referências exatas obtidas por índice ou por um slice de scan
  ao vivo com orçamento explícito.

O classificador pertence ao domínio e é uma função pura sobre bytes amostrados
e snapshots normalizados do mapa de regiões/módulos. Ele não conhece JSON,
MCP, logging, handles, Win32, `/proc`, filesystem ou threads. Application
coordena snapshots e leituras por `ProcessSession`; Infrastructure continua a
ser a única camada que toca APIs nativas; Protocol/MCP valida e apresenta o
contrato.

### Região, módulo e RVA

Regiões e módulos usam intervalos semiabertos `[start, end)`. Ausência de região
ou módulo é um resultado válido: o campo correspondente é `null`. A resposta
expõe somente atributos já disponíveis no mapa (`readable`, `writable`,
`executable`, `private`, nome limitado) e não infere uma proteção que o provider
não informou. `rva` só existe quando o endereço pertence de fato ao módulo.

### Candidatos de objeto e vtable

O serviço lê uma janela `lookbehind_bytes` limitada antes do endereço, mais os
bytes necessários para testar uma base exatamente no endereço. A faixa é
recortada sem underflow/overflow à região legível que contém o endereço. Cada
posição com um ponteiro completo e alinhada à largura do alvo pode ser um
`object_address`; `field_offset` é apenas a diferença verificada
`inspected_address - object_address`.

O valor no início candidato é tratado como possível vptr. Na primeira versão,
ele só segue para a fase de ranking quando aponta para uma região legível,
**não gravável** e associada a um módulo. A aplicação lê até `K` entradas da
possível vtable, com limites próprios. O domínio conta quantas entradas
completas apontam para regiões executáveis e registra também short reads,
módulo da vtable e coerência entre módulos. Nenhum desses sinais isolado
confirma um objeto.

Todo item usa obrigatoriamente:

- `classification: "probable"`;
- `confidence: low | medium | high`;
- `evidence`, uma lista limitada de fatos observados;
- `provenance`, uma lista limitada das fontes derivadas;
- `field_offset`, nunca chamado de offset de propriedade confirmado.

Mesmo `confidence: high` continua sendo **provável**. A tool não inventa nome
de classe, tipo, símbolo ou propriedade. Múltiplos candidatos são preservados e
ordenados deterministicamente por score derivado, quantidade/proporção de
entradas executáveis, qualidade da região e, como desempate, menor
`field_offset` e menor endereço. A resposta informa truncamento quando o limite
de candidatos escondê-los.

### Referências

Referências são opt-in e têm dois modos mutuamente exclusivos:

- `index`: consulta um `index_id` pertencente à mesma sessão, conforme
  ADR-0018/Spec 0010. A resposta preserva cobertura, orçamento e proveniência
  do build do índice; índice parcial ou stale nunca produz um vazio conclusivo;
- `live_scan`: executa um slice explícito do scan reverso, reutilizando os
  contratos de ADR-0011 e a cobertura/retomada/motivos da ADR-0012. Exige
  `byte_budget` e `result_limit`; não existe scan global oculto.

O modo `index` pagina por cursor opaco vinculado à sessão, alvo, pointer size,
filtros e índice. O modo `live_scan` retoma exclusivamente pelo
`resume_token` autoritativo da ADR-0012; `next_start_address`, quando presente,
é apenas diagnóstico. Ambos devolvem orçamento, cobertura, `complete`, estado
de continuação e `truncation_reasons`. Um array vazio só significa “nenhuma
referência” quando `complete` for verdadeiro. O alvo das referências é
exatamente o endereço inspecionado; para consultar um `object_address`
provável, o cliente faz outra chamada explícita.

### Arquitetura do alvo

Endereços permanecem `uint64_t`, mas a decodificação little-endian usa
exatamente 4 bytes em x86 e 8 bytes em x64. A primeira versão não usa
`sizeof(void*)` do processo MCP como default: `pointer_size` é obrigatório até
que a porta de processo exponha arquitetura do alvo com proveniência. Valores
de 64 bits não são silenciosamente truncados em modo x86.

### Limites e ausência de evidência

`lookbehind_bytes`, candidatos examinados/devolvidos, probes de vtable, `K`,
entradas/evidências por candidato, referências e bytes de scan possuem tetos
rígidos. A memória usada é proporcional a esses limites, nunca ao tamanho total
do processo, exceto pelo scan ao vivo já orçado.

Se a região, módulo, bytes suficientes ou evidência mínima não existirem, a
tool retorna `null`, array vazio e/ou uma limitação tipada. Não substitui
ausência por endereço zero, módulo desconhecido, vtable sintética ou confiança
presumida. Falhas nativas são traduzidas para erros seguros.

## Consequências

- a heurística passa a ser centralizada, reproduzível e testável sem processo
  real;
- o cliente recebe fatos derivados pequenos em vez de grandes dumps de bytes;
- falsos positivos continuam possíveis e são explicitados por
  `probable`/`confidence`/`evidence`/`provenance`;
- snapshots de memória, regiões e módulos não são atômicos; timestamps e
  limitações tornam essa condição visível;
- `index` evita I/O repetido; `live_scan` permanece disponível com custo e
  cobertura explícitos;
- não há escrita, injeção, chamada de função remota, mudança de proteção,
  elevação, stealth ou bypass;
- nenhuma dependência externa é adicionada.

## Segurança e observabilidade

A tool exige `session_id` existente e mantém a classe de acesso read-only. Todo
cálculo de faixa, RVA, `field_offset` e tamanho de tabela verifica
overflow/underflow. Cursor e índice não atravessam sessão nem snapshot.

Logs estruturados ficam em `stderr` e podem conter apenas correlação opaca,
duração, contagens, bytes lidos, fonte de referências, cobertura e motivo de
término. Endereço alvo, bytes, vptrs, entradas, referências, nomes/paths de
módulo, cursores, `resume_token` e argumentos completos não entram em logs.
`stdout` continua exclusivo de JSON-RPC/MCP.

## Verificação

A [Spec 0011](../specs/0011-inspect-address.md) fixa schema, limites, ranking,
testes com `SparseFakeSession`, benchmarks e critérios de aceite.
