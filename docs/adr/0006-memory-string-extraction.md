# ADR-0006 — Extração de strings no servidor

Status: aceito

## Contexto

Ler um módulo inteiro com `memory_debug.read` para localizar nomes de campos
e tags de depuração produz um payload hex grande o suficiente para estourar
limites de tokens do cliente MCP, obrigando a salvar em arquivo e pós-
processar fora do protocolo. O caso de uso "encontrar classes e campos sem
ler código-fonte" depende quase sempre de strings ASCII/UTF-16 legíveis
embutidas no binário ou no heap (nomes de campos usados em `printf`/`cout`,
tags de alocador, mensagens de log), não dos bytes crus.

## Decisão

Adicionar a tool `memory_debug.strings`, implementada inteiramente na camada
de aplicação (`MemoryDebugService::extract_strings`) sobre `ProcessSession::read`
e `regions()`/`modules()` já existentes — nenhuma porta nova de domínio é
necessária. O servidor varre o intervalo pedido (ou módulo/região indicada),
identifica sequências imprimíveis (`ascii` ou `utf16le`) com comprimento
mínimo configurável e devolve `{address, text, encoding}` por ocorrência, já
truncado a `max_string_result_length` por item.

A operação reaproveita `SecurityPolicy::authorize_scan` (mesmo `byte_budget`,
`result_limit`, `writable_only` de `scan_exact`) — nenhum gate de ambiente
novo é necessário porque continua sendo leitura dentro dos limites já
auditados.

## Consequências

- elimina a necessidade de dump manual + script externo para encontrar nomes
  de campos/classes;
- texto extraído é tratado como memória sensível: nunca aparece em logs
  (`stderr`), apenas em `data` da resposta;
- resultados longos continuam sujeitos a `truncated: true`, igual a
  `scan_exact`;
- não há novo estado persistente no servidor além do já existente por sessão.
