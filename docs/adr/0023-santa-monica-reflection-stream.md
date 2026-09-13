# ADR-0023 — Stream limitado de snapshots de reflexão Santa Monica

Status: aceito e implementado como codec/reader em `argos_infrastructure`
(`encode_reflection_frame` e `ReflectionStreamReader`), sem transporte.

## Decisão

O snapshot normalizado usa frames binários little-endian, com codec e reader
em `argos_infrastructure`. O domínio continua recebendo registros tipados
pela porta `SantaMonicaRuntimeReader`. O formato não é uma struct C++ copiada
para o wire, não transporta ponteiros e não executa comandos de gameplay.

Um stream representa uma única descoberta: `begin`, zero ou mais `record`,
`end`. Header de 32 bytes, sem padding dependente de compilador:

| Offset | Campo | Representação |
|---|---|---|
| 0 | magic | bytes ASCII `SMRF` |
| 4 | versão | u16, `1` |
| 6 | comprimento do header | u16, `32` |
| 8 | kind | u16: begin `1`, record `2`, end `3` |
| 10 | reservado | u16, zero |
| 12 | comprimento do payload | u32, até `1 MiB - 32` |
| 16 | request ID | u64 não zero, esperado pelo receptor |
| 24 | sequência | u64, inicia em `1`, incrementa por frame |

O reader rejeita kind/versão desconhecidos, campos reservados, gaps/repetições
de sequência, request diferente, truncamento e payload residual. Uma falha
invalida definitivamente a instância e fecha seu stream; não há tentativa de
ressincronizar bytes hostis. Ao consumir `end`, fecha o stream dedicado: bytes
posteriores não pertencem à transferência e nunca são interpretados.

Inteiros são codificados byte a byte; bool é u8 `0`/`1`; optionals usam bool e
o valor somente quando presentes. Strings são u32 de comprimento seguido de
bytes ASCII imprimíveis, sem NUL; metadados respeitam o limite negociado de
até 4 KiB e identidades o teto de 128 bytes. SHA-256 tem 32 bytes crus.
Todos os comprimentos/contagens são validados antes de alocar o destino.

Payloads begin/end contêm, nesta ordem: schema de perfil u32, profile ID,
digest do perfil, digest da bridge, bridge version u32, protocol version u32,
número de módulos u32 (1–64), módulos (nome, image size u64, digest de arquivo),
arquitetura u8 (`1` = x64), origem u8 (`0` bridge, `1` reader nativo; ver
[ADR-0026](0026-santa-monica-native-type-reader.md)),
identidade de processo, época de bridge, geração
u64, consistência u8 (`0` best-effort, `1` stable, `2` unstable) e cobertura bool.

Record começa com tag u8 e os campos na ordem a seguir:

| Tag | Conteúdo |
|---|---|
| 1 | type ID u64, nome, size u64, base opcional u64 |
| 2 | owner type u64, nome, offset u64, size u64, field kind u8, type opcional u64, enum opcional u64 |
| 3 | enum ID u64, nome |
| 4 | owner enum u64, nome, valor decimal textual |
| 5 | function ID u64, nome, assinatura descritiva |

Field kind é fechado: scalar `0`, object `1`, pointer `2`, array `3`, map `4`,
enumeration `5`. IDs são chaves de metadados normalizados, nunca endereços.
Semântica de referências, herança, bounds e inteiros continua validada pelo
catálogo do domínio, inclusive depois de um decode estrutural bem-sucedido.

## Limites e lifetime

Defaults: frame completo de até 1 MiB, 64 MiB totais por descoberta, até
100.000 records e deadline total de 5 s. A configuração só pode reduzir os
tetos. Header e budget agregado são verificados antes da alocação do payload.
O reader aceita fragmentação arbitrária e EOF prematuro é erro. Checks de
cancelamento/deadline ocorrem antes/depois de cada leitura. A porta de stream
deve cumprir o deadline durante I/O; o reader não preempta uma implementação
bloqueada que viole esse contrato. Nenhuma thread ou lock é criado pelo codec.

## Fronteira de confiança

Este incremento implementa codec e reader, não transporte/handshake. O
receptor deve receber um stream dedicado previamente autenticado e um request
ID novo por descoberta, gerado pelo servidor. ID e sequência detectam troca
e repetição dentro do stream; **não autenticam o peer nem impedem replay entre
conexões por si só**. Campos de identidade e `stable` continuam sujeitos à
validação nativa e à garantia de snapshot do perfil, não são atestações.

ACL, bootstrap protegido, segredo/época, validação da imagem carregada e
dispatcher permanecem pendentes. Nenhuma tool MCP ou export de bridge é
habilitado por esta ADR; não há fallback para aceitar bytes do cliente MCP.

## Verificação

Testar bytes de header independentes do encoder, round-trip de todas as
variantes, integração com `ReflectionCatalog`, fragmentação de um byte,
truncamento, comprimentos excessivos antes de alocação/leitura do corpo,
versões/tags/bools inválidos, payload residual, sequência/request incorretos,
budget agregado, deadline, cancelamento e fechamento em erro/sucesso.

Executado em `argos_santa_monica_stream_tests`. Cada rejeição estrutural tem
razão fechada própria (`invalid_magic`, `invalid_header_length`,
`invalid_frame_kind`, `invalid_reserved_field`, `unexpected_request_id`,
`unexpected_sequence`, `unexpected_frame_kind`, `invalid_record_tag`,
`invalid_field_kind`, `invalid_architecture`, `invalid_consistency`,
`invalid_module_count`, `invalid_string_length`, `invalid_string_byte`,
`invalid_bool`, `invalid_snapshot_source`, `truncated_payload`,
`trailing_payload_bytes`) e as de limite
usam `frame_too_large`, `wire_budget`, `record_budget` ou `stream_deadline`.
Erros do transporte são reduzidos a `stream_read_failed`, `unexpected_eof` ou
`stream_contract_violation`, sem repassar diagnóstico nativo.

Referências: [ADR-0022](0022-santa-monica-kinetica-runtime-instrumentation.md),
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).
