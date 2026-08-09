# ADR-0007 — Scan reverso de ponteiro

Status: aceito

## Contexto

Encontrar a struct "dona" de um campo cujo endereço já é conhecido é uma
operação básica de introspecção (dado o endereço de um `const char*` ou de
um objeto, achar quem o referencia). Hoje isso só é possível reaproveitando
`scan_exact` com o endereço-alvo codificado manualmente em hexadecimal
little-endian pelo cliente — processo sujeito a erro de codificação e nada
descobrível sem already saber o truque.

## Decisão

Adicionar `memory_debug.scan_pointers_to`, implementada em
`MemoryDebugService::scan_pointers_to` como um invólucro fino sobre a mesma
rotina interna de varredura de `scan_exact`: o serviço codifica
`target_address` em 4 ou 8 bytes little-endian (conforme `pointer_size`) e
delega ao mecanismo de varredura já existente. Não é criada nenhuma rota de
leitura nova; o resultado tem o mesmo formato de `ScanResult`
(`matches`, `bytes_scanned`, `truncated`).

## Consequências

- remove a necessidade de codificação manual de endereço pelo cliente;
- reaproveita 100% dos limites e do código de varredura já revisados de
  `scan_exact` — sem `SecurityPolicy` nova;
- a tool é autoexplicativa (nome e parâmetros descrevem a intenção), o que
  reduz a chance de um agente reinventar a técnica incorretamente.
