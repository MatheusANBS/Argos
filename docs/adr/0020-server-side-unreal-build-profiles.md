# ADR-0020 — Perfis de build Unreal configurados pelo operador

Status: aceito e implementado

## Contexto

O modo explícito de reflexão runtime exige que cada cliente conheça os RVAs de
`GUObjectArray` e `FNamePool`. Sessões e chats novos não compartilham esse
contexto. O contrato da ADR-0019 já reserva `mode: "profile"` e a origem
`build_profile`, mas a primeira entrega não possuía um registro de fingerprints.

Ligar `mode: "auto"` sem uma identidade de build também não é suficiente: a
descoberta multipadrão ainda não existe, e aceitar RVAs somente pelo nome do
executável poderia reutilizar offsets depois de uma atualização incompatível.

## Decisão

O servidor aceita perfis de build somente pela configuração do operador em
`ARGOS_MCP_UNREAL_BUILD_PROFILES`. Cada registro imutável contém:

- ID da build e `profile_id` de layout;
- nome exato do módulo e `SizeOfImage` esperado;
- RVA e bytes de uma assinatura de 8–64 bytes;
- RVAs de `GUObjectArray` e `FNamePool`.

O cliente MCP não cria nem altera registros. `mode: "profile"` procura uma
correspondência; `mode: "auto"`, atrás do gate independente existente, tenta
primeiro os mesmos perfis registrados. A descoberta multipadrão permanece um
fallback futuro e retorna `unsupported` quando não existe registro aplicável.

Uma correspondência exige nome, tamanho e assinatura exatos na memória do
módulo autorizado. Zero resultados retorna `not_found`; mais de um retorna
`invalid_argument` por ambiguidade. Depois da correspondência, os RVAs passam
por aritmética checked e todas as invariantes estruturais da ADR-0019 continuam
obrigatórias antes da publicação do contexto. A proveniência inclui
`module_fingerprint` e `root_origin: "build_profile"`.

O parser de configuração é bounded: até 64 registros, 32 KiB totais e
assinaturas de até 64 bytes. Registros inválidos não são parcialmente aceitos.
Não há leitura de paths fornecidos pelo cliente, biblioteca externa, escrita,
injeção ou execução no alvo.

## Consequências

- chats e clientes novos podem descobrir uma build conhecida sem conservar
  roots no histórico;
- reiniciar o processo não invalida os RVAs, pois eles são resolvidos contra a
  nova base do módulo;
- uma atualização do binário falha fechada pela identidade da build e precisa
  de um novo registro do operador;
- `mode: "auto"` torna-se útil para builds registradas, mas não promete suporte
  genérico a qualquer Unreal;
- configurações locais podem conter bytes de assinatura do executável e não
  devem ser registradas em logs.

## Verificação

Fixtures sintéticas cobrem profile/auto, reinício de sessão, mismatch de
assinatura, ambiguidade, parser inválido, roots conflitantes e proveniência. A
validação real deve usar somente um alvo autorizado e confirmar que nenhum
conteúdo de memória ou configuração aparece em `stdout`/logs.
