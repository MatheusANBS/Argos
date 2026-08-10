# Revisão de eficiência e capacidade — 2026-08-09

## Resultado

Esta rodada removeu os maiores custos acidentais do servidor, ampliou o
contrato de análise e endureceu o transporte. "Infinitamente rápido e
completo" não é uma meta mensurável; o critério usado foi reduzir I/O,
alocações e volume de protocolo sem elevar os limites defensivos nem habilitar
escrita por padrão.

## Medição do protocolo

Benchmark persistente de `tools/list` em MSVC Release, incluindo leitura da
frame, parse, dispatch, serialização e `stdio`:

| Variante | Mediana | Faixa | Resposta | Observação |
|---|---:|---:|---:|---|
| baseline anterior ao catálogo cacheado | 1.186 req/s | 1.159–1.201 | 21.561 B | 5 amostras de 500 requests |
| estado final, sem IPO | 2.008 req/s | 1.937–2.096 | 32.939 B | 8 amostras de 3.000 requests |
| estado final, com IPO | 1.879 req/s | 1.802–2.028 | 32.939 B | 8 amostras de 3.000 requests |

O estado final sem IPO processou aproximadamente 69% mais requests por segundo
que o baseline observado, mesmo com uma resposta 53% maior devido a
`outputSchema`. Como as duas rodadas têm cargas e durações diferentes, isso é
um resultado fim a fim, não uma atribuição causal isolada.

IPO/LTO reduziu o executável de 641.536 para 621.568 bytes (-3,11%), mas perdeu
6,4% de throughput nesse hot path; todas as oito comparações favoreceram a
variante sem IPO. A opção `ARGOS_ENABLE_IPO` foi mantida para experimentos, mas
o preset Release não a habilita.

## Reduções estruturais de custo

| Caminho | Antes | Agora |
|---|---|---|
| snapshot de scan | cópia profunda de todos os candidatos sob mutex | snapshot imutável COW por `shared_ptr`; CAS evita publicar geração obsoleta |
| armazenamento de candidato | uma alocação de `vector<byte>` por candidato | valor de até 8 bytes inline; `ScanCandidate` ocupa 16 bytes |
| `scan_next` contíguo | uma leitura nativa por candidato | runs limitadas por `max_read_bytes`; 262.144 `i32` contíguos podem cair de 262.144 para 16 leituras |
| `read_batch` | uma leitura por item | união de intervalos adjacentes/sobrepostos; até 256 itens podem virar uma leitura, com fallback seguro em short-read |
| `scan_pointer_chains` | nova varredura por item da fronteira | uma varredura multi-alvo por profundidade |
| `scan_first`/strings | alocações por chunk e teste em todo byte | buffers reutilizados e iteração somente nos alinhamentos candidatos |
| catálogo MCP | schemas reconstruídos e copiados em cada `tools/list` | catálogo construído e ordenado uma vez |
| captura de output | `string::erase(0, n)`, O(capacidade) por append cheio | buffer circular, O(bytes de entrada) |

As rotas agrupadas preservam ordem e semântica de erro. Short-read em uma run
faz fallback apenas para os itens não confirmados; cancelamento é observado
entre runs e durante seu processamento.

## Capacidades acrescentadas

- `regions` ganhou filtros por atributos/faixa/tamanho/nome e paginação;
- `address_space_summary` dimensiona o alvo sem transferir milhares de regiões;
- `scan_first` informa cobertura real, inclusive falha parcial de leitura;
- `scan_first` e `scan_next` aceitam valores e deltas decimais com validação de
  largura, sinal, overflow e faixa de `f32`/`f64`;
- `scan_results` devolve página autocontida com geração, total, offset,
  quantidade retornada e truncamento;
- cadeias reversas usam uma passagem multi-alvo por nível;
- Release oferece IPO opt-in, medido e rejeitado como default quando regrediu.

## Protocolo e hardening

- compatibilidade dual-era: MCP `2026-07-28` por request e legado
  `2025-11-25`/`2025-06-18`;
- `server/discover`, ordem determinística, cache hints, `resultType`, identidade
  do servidor, `outputSchema` e erro JSON-RPC `-32602` para tool desconhecida;
- cancelamento suprime a resposta cancelada e libera a janela `busy` antes de
  publicar a resposta concluída;
- frames JSON: 8 MiB, 128 níveis e 65.536 nós; serializer iterativo e números
  não finitos convertidos em `null`;
- contagens de leitura maiores que o span fornecido são rejeitadas;
- aritmética delta assinada usa representação modular explícita, sem signed
  overflow; conversão `f64→f32` valida faixa antes do cast;
- shutdown dos pipes Win32 não depende de uma janela frágil de
  `CancelSynchronousIo`.

## Validação

- MSVC x64 Debug clean: unitários e contrato passaram;
- MSVC x64 Release, com e sem IPO: unitários e contrato passaram;
- repetição Debug: 100/100 unitários e 100/100 contrato;
- repetição Release sem IPO: 100/100 unitários e 100/100 contrato (200/200);
- ASan MSVC: 20/20 unitários e 20/20 contrato (40/40);
- repetição paralela deixou de compartilhar a mesma fixture temporária Unity;
- `git diff --check` limpo; não há `TODO`, `FIXME` ou marcador de diagnóstico no
  escopo alterado.

UBSan não está disponível no preset MSVC deste projeto. A execução Release+IPO
foi particularmente útil: revelou um cast floating-point fora da faixa que o
ASan não sinalizava e que já foi eliminado.

## Limites ainda abertos

1. `scan_first` ainda precisa de `resume_token`/deadline para cobrir alvos
   maiores com um único `scan_id`.
2. Anotação, clustering e amostragem temporal de candidatos continuam nas
   fases 2–5 do roadmap.
3. O orçamento de `scan_pointer_chains` ainda é repartido antecipadamente por
   profundidade; um primeiro nível sem match pode deixar orçamento sem uso.
4. O cursor de output ainda compacta stdout/stderr em 32+32 bits; processos com
   mais de 2 GiB de output cumulativo precisam de cursor opaco 64+64 bits.
5. `regions` pagina por padrão; clientes legados que ignoram `truncated` devem
   ser migrados ou receber uma política de compatibilidade por era.
6. No protocolo moderno, o servidor privilegia `structuredContent` sem duplicar
   todo o JSON em `TextContent`. Isso reduz volume, mas clientes que consomem
   somente ContentBlocks precisam usar o caminho legado ou ganhar fallback.
7. A distinção `image` versus `mapped` no resumo depende de enriquecer o modelo
   de regiões dos providers de plataforma.

O plano de continuidade e as métricas de sessão real permanecem em
`docs/specs/0007-roadmap-eficiencia-agente.md`.
