# ADR-0019 — Reflexão Unreal em runtime sem PDB

Status: aceito e implementado (execução síncrona; perfis de build implementados
pela ADR-0020; jobs e descoberta multipadrão permanecem propostos)

## Contexto

O suporte Unreal atual consulta exclusivamente o PDB correspondente ao módulo
carregado. Esse caminho é reproduzível e continua sendo a fonte preferida para
layout nativo, mas builds distribuídas frequentemente não preservam símbolos.
Nesses casos, `memory_debug_unreal_type` e
`memory_debug_unreal_reflection` não conseguem enumerar classes, objetos ou
`FProperty`, embora o próprio runtime mantenha metadados de reflexão.

ADR-0005 deliberadamente proibiu transformar scans genéricos em layouts
confirmados. Essa proteção permanece necessária: `GUObjectArray`, `FNamePool`,
`UObject`, `UStruct` e `FProperty` variam entre versões, configurações e forks
do engine. “Sem PDB” não significa “sem perfil de layout” e uma assinatura
isolada não prova a versão nem a estrutura encontrada.

A enumeração também é uma operação sobre memória viva e mutável. Counts,
chunks e listas encadeadas podem mudar entre leituras; ponteiros ou tamanhos
hostis não podem dirigir alocações, loops ou leituras sem limites.

## Decisão

Será criada uma porta própria `UnrealRuntimeIntrospector`, separada de
`TypeMetadataProvider`. Ela recebe um leitor abstrato somente-leitura, o mapa
de regiões, os módulos e um perfil explícito. O parser e os validadores
pertencem ao domínio/aplicação e não dependem de JSON, DbgHelp, Win32 ou Linux.
O adapter nativo apenas fornece bytes e metadados do processo.

O pipeline suportado é:

1. localizar ou receber as raízes de `GUObjectArray` e `FNamePool`;
2. selecionar um perfil versionado de layout;
3. validar estruturalmente raízes, counts, capacity, chunks e ponteiros;
4. enumerar slots vivos de `UObject`;
5. resolver `ClassPrivate`, `UClass`, `UStruct` e `SuperStruct`;
6. decodificar nomes por `FNamePool` com bounds estritos;
7. percorrer `FField`/`FProperty` ou, em um perfil legado separado,
   `UField`/`UProperty`;
8. produzir nomes, herança, offsets internos, `element_size`, `array_dim`,
   flags e proveniência — não valores de propriedades por padrão.

Perfis são registros imutáveis, identificados e testados. Cada perfil declara
família/versão suportada, pointer size, endianness, modelo de object array e de
names, offsets estruturais e invariantes. Perfil desconhecido ou incompatível
retorna `unsupported` com reason `unsupported_profile`; não há fallback
silencioso para offsets “comuns”.

Modo de descoberta (`explicit`, `profile`, `auto`) e origem observada não são o
mesmo campo. Há quatro origens possíveis para as raízes, sempre visíveis:

- `explicit_rva`: módulo + RVA fornecido pelo cliente e validado;
- `explicit_address`: endereço absoluto válido somente na sessão corrente;
- `build_profile`: RVA conhecido e vinculado ao fingerprint de uma build;
- `signature_candidate`: resultado de scan multipadrão, ainda heurístico.

Uma raiz localizada por assinatura permanece candidata até passar todas as
invariantes do perfil. `confidence: high` só é permitido quando perfil,
identidade da build, raízes e estruturas percorridas foram integralmente
validados. Resultados parciais ou heurísticos usam confiança menor e incluem
`evidence`, `failed_invariants` e proveniência. Nenhuma evidência é promovida a
fato apenas porque um nome legível foi encontrado.

A superfície MCP será distinta das tools PDB atuais:

- `memory_debug_unreal_runtime_discover`;
- `memory_debug_unreal_runtime_classes`;
- `memory_debug_unreal_runtime_type`;
- `memory_debug_unreal_runtime_objects`;
- `memory_debug_unreal_runtime_release`.

Operações que varrem módulo/object array usam o mecanismo de jobs assíncronos
da Spec 0008: `AnalysisJobKind::unreal_runtime` no mesmo
`AnalysisJobManager`, fila e pool usado por scans/pointer-index, controlado por
`job_status/results/cancel/release`. Não há pool Unreal separado. Um
`runtime_id` guarda somente perfil, raízes validadas, identidade do processo e
proveniência; não transforma a memória viva em snapshot eterno. Ele exige
`session_id` em toda query, possui quotas/TTL/release próprios e não é removido
por `job_release`; release com job dependente ativo retorna `invalid_state` em
vez de cancelá-lo implicitamente. Cada página revalida identidade e os tuples
`(object_index, serial, pointer)` antes/depois do parse, não somente counts. Se
não conseguir uma leitura coerente, o job falha com `unstable_snapshot` e não
publica draft misto.

O parser nunca chama função no alvo, injeta código/DLL, cria thread remota,
altera proteção ou escreve memória. Descoberta automática é opt-in e limitada
a módulos pertencentes à sessão. O recurso inteiro nasce atrás de gate geral e
allowlist de perfis server-side; auto discovery exige um segundo gate,
desligado por padrão. O request nunca habilita capacidade desativada. A
enumeração expõe metadados; ler valores de instâncias continua exigindo uma
tool de leitura explícita e a política normal da sessão.

Esta decisão **estende**, quando aceita e implementada, ADR-0005. Ela não
rebaixa a confiança do caminho PDB e não muda o significado das tools atuais.
PDB e runtime permanecem fontes distintas e podem ser comparadas quando ambas
existirem.

Não será adicionada dependência externa na primeira implementação. Uma futura
biblioteca de parsing ou signatures exige revisão de dependência e ADR próprio.

## Consequências

- builds Unreal sem PDB passam a ter uma rota limitada e auditável para
  reflexão que já existe no processo;
- suporte é por perfil, não uma promessa de compatibilidade com qualquer UE;
- PDB continua sendo a fonte preferida para layout nativo completo;
- o domínio ganha um leitor/parser runtime próprio, em vez de acoplar memória
  viva ao provider de arquivos de símbolo;
- descoberta multipadrão e jobs assíncronos tornam-se dependências de
  implementação para o modo automático e enumerações grandes;
- respostas ficam maiores e podem revelar nomes/classes do jogo, exigindo
  paginação, quotas e logs sem conteúdo;
- alterações concorrentes do engine podem produzir `unstable_snapshot`, que é
  um resultado seguro e esperado;
- novos perfis exigem golden fixtures, fuzzing dos parsers e revisão de
  segurança antes de serem habilitados.

## Verificação

A [Spec 0012](../specs/0012-unreal-runtime-reflection.md) define os contratos,
invariantes, limites, proveniência, testes sintéticos e critérios para aceitar
um perfil. O threat model deverá ser atualizado antes da implementação.
