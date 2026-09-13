# ADR-0022 — Instrumentação runtime Santa Monica/Kinetica por build

## Status

Aceito em 2026-09-12 por aprovação do operador; implementação incremental em
andamento. Aceitação da decisão não significa suporte validado a uma build.

Revisado em 2026-09-12: entrega incremental, canal autenticado e operações
mutáveis com deduplicação e resultado incerto explícitos. Esta ADR ainda não
atesta suporte a uma build real.

Evolução implementada: identidade e catálogo no domínio, codec (ADR-0023),
handshake (ADR-0024), transporte/peer sintético e tools (ADR-0025), reader
nativo inicial (ADR-0026) e reflexão nativa expandida (ADR-0027). Há validação
somente leitura na instalação Steam 11168363; o transporte autenticado foi
validado com peer controlado. Bridge no jogo, atestação da imagem, dispatcher
e capacidades mutáveis continuam pendentes; comparar identidade no domínio
não autentica um peer.

## Contexto

O suporte atual do Argos a engines é orientado a evidência: PDB, metadata
Unity, reflexão Unreal em runtime e leitura externa de memória. Isso não basta
para enumerar os tipos reais de *God of War* (2018), explorar todos os itens
existentes e conceder itens pelo fluxo legítimo da engine.

O projeto público
[`godofwar-gameplay-tweaks`](https://github.com/Nukem9/godofwar-gameplay-tweaks)
mostra, para uma build PC, tabelas de RTTI com tipos, campos, herança e enums,
registries SLI de funções/propriedades e carregamento de scripts Lua. Ele
também carrega cedo como `version.dll` e instala hooks por assinatura. Isso é
evidência de uma rota técnica, não contrato oficial da engine nem fonte de
código para o Argos: o repositório declara que não possui licença.

Uma bridge de mera presença (Spec 0013) não cumpre o objetivo. Por outro lado,
uma injeção genérica transformaria o MCP em executor remoto de payloads. A
superfície precisa ser poderosa, mas vinculada a uma engine, build, bridge e
contratos conhecidos.

## Decisão

Adicionar futuramente o adapter **Santa Monica/Kinetica runtime** para builds
x64 explicitamente perfiladas, com três planos:

1. **Reflexão**: RTTI, enums e registries SLI com proveniência, paginação e
   validação estrutural.
2. **Script**: observação Lua e, após comprovar isolamento e quotas no perfil,
   execução de fonte Lua na VM do jogo com capacidades explícitas.
3. **Gameplay**: inventário, catálogo de itens, invocação SLI e
   concessão/remoção de itens pela rota interna validada.

O domínio recebe portas tipadas (`SantaMonicaRuntimeReader` e
`SantaMonicaBridgeChannel`) e não conhece MCP, JSON, Win32, Lua C API,
Detours, DLL proxy nem PE. A infraestrutura Windows implementa carga,
assinaturas, RTTI, SLI, Lua e ABI nativa; o protocolo MCP valida e serializa a
Spec 0014.

### Perfil e modo de carga

Todo perfil é configurado pelo operador e contém identificador, módulo,
arquitetura, tamanho, fingerprint criptográfico, layouts/assinaturas RTTI-SLI,
modo permitido (`attach`, `early_load`), versão de bridge e versão de
protocolo. A identidade do módulo precisa corresponder por completo; não há
fallback por assinatura genérica nem compartilhamento de perfil entre patches.
O perfil também versiona schema, digest do artefato de bridge, capacidades e
allowlist de funções/efeitos. A identidade cobre instância do processo,
arquivo e imagem carregada com regras de ASLR/relocations; comparar apenas
arquivo em disco ou PID não é suficiente.

`attach` utiliza a rota de carregamento aprovada da Spec 0013 em processo já
aberto, preservando seus gates. Essa bridge ainda não oferece IPC, hooks ou
dispatcher: são entregas novas, não recursos implícitos na prova de presença.
Discover nunca injeta nem inicia processo como efeito oculto.
`early_load` observa um jogo iniciado pelo operador com bridge antes do
bootstrap Lua; é necessário para observar scripts carregados no início.
A técnica de carga antecipada (por exemplo, proxy DLL em diretório de teste) pertence à
infraestrutura e nunca é escolhida pelo cliente MCP. Automatizar o início
exige contrato adicional da Spec 0005; substituição/exportação de scripts não
faz parte da primeira entrega.

### Protocolo e contexto

O canal local autentica peers, restringe ACL e acesso remoto, vincula sessão,
processo, perfil, artefato e época com bootstrap protegido e segredo efêmero.
Frames limitados antes da alocação têm opcodes fechados, sequência e proteção
contra replay. A Spec 0014 exige concretizar e testar wire format, bootstrap
e transporte na etapa 1, antes de executar comandos de engine.

A aplicação possui um `SantaMonicaRuntimeManager` com snapshots imutáveis,
handles por geração e registros limitados de operação. Releitura de cabeçalhos
é apenas `validated_best_effort`; `stable` exige mecanismo de consistência
comprovado pelo perfil. Completude se refere ao escopo observado, não ao jogo
inteiro. Mudança de processo/módulo/save invalida os handles afetados.

### Execução no processo

Lua e gameplay são capacidades de modding deliberadas, desabilitadas por
padrão e protegidas por gates separados. Mesmo habilitadas, a bridge aceita
somente identificador opaco de função SLI explicitamente permitida pelo perfil,
argumentos validados pelo RTTI, identificador de item do catálogo e fonte Lua
limitada para a VM validada. Publicação no registry não autoriza invocação. Ela
não recebe endereço, RVA, export, DLL, shellcode ou função nativa arbitrária.

Os comandos entram em fila e são executados no tick/main thread definido pelo
perfil; nunca por thread remota que chama diretamente a engine. Há um owner e
uma operação engine/Lua ativa por processo/época, inclusive entre sessões.
Release, detach, expiração e shutdown fecham admissão e descartam fila ainda
não iniciada. Recursos de callbacks ativos permanecem vivos até cleanup
seguro; inicialização, I/O e waits ficam fora de `DllMain`/loader lock.
A primeira entrega não faz unload de DLL/hook em processo vivo; esse contrato
exige quiescência própria. Shutdown local não espera indefinidamente pelo alvo.

Mutações usam `idempotency_key` e registro próprio, separado dos jobs de scan
da Spec 0008, que exclui execução/escrita no alvo. As tools de status, cancel e
release da Spec 0014 tornam o resultado observável mesmo quando a resposta
inicial se perde. Tombstones limitados impedem repetição durante a retenção;
não há exactly-once entre crashes. Timeout após efeitos produz
`outcome_unknown`, nunca rollback presumido ou reexecução automática.
Resultado incerto bloqueia mutações até quiescência e reconciliação; leitura
com callback ainda ativo, release ou expiração do registro não libera o alvo.

Lua exige prova da ABI da VM e ambiente sem acesso transitivo a loaders,
shell, filesystem, rede, FFI, registry/debug ou callbacks não aprovados.
Sem isolamento, quotas de memória e cleanup verificáveis, a execução fica
indisponível. Contagem de instruções não interrompe callback C bloqueado:
deadlines são cooperativos, sem matar thread, fechar a VM do jogo ou liberar
estado ainda em uso. Lua irrestrito exigiria outra decisão de segurança.

### Dependências

Esta ADR não adiciona dependências. O projeto de referência usa Detours. Se
Detours for adotado, uma ADR específica deve registrar versão imutável,
origem, licença MIT, lock, política de atualização, threat model e fallback.
Seu uso permanece restrito à bridge Windows, fora do domínio e da API pública.

## Consequências

- O Argos poderá suportar exploração e modding por build conforme a evidência
  e os critérios de cada etapa; a primeira entrega é somente leitura.
- `grant_item` pode preservar identidade de instância, equipamento, atributos
  e persistência que uma escrita externa cega não conhece.
- Lua e invocação SLI são uma fronteira de confiança maior que a Spec 0013 e
  serão expostos claramente no startup, respostas e logs.
- Builds sem perfil retornam `unsupported`; plausibilidade não substitui
  validação de build.
- Catalogar tipos não prova catálogo completo de itens nem transação de
  inventário. Grant pode alterar pilhas ou criar várias instâncias; efeito em
  memória e persistência confirmada são resultados distintos.
- O primeiro escopo é Windows x64 e offline/autorizado; não inclui bypass de
  DRM, anticheat, EDR, stealth, privilégio elevado ou outro usuário.

## Verificação exigida

1. Fixtures de RTTI/SLI válidas, inválidas, oversized e mutáveis.
2. Testes de gates, perfil incompatível, paginação, Lua inválido e marshaling
   SLI impossível.
3. Alvo controlado para fila de main thread, cancelamento e shutdown.
4. Cópia autorizada de save: item visível, equipável quando aplicável,
   persistido após restart, sem corrupção de inventário.
5. Warnings altos, testes e sanitizers aplicáveis; logs em `stderr` e `stdout`
   somente MCP.
6. Handshake/ACL, replay, troca de época, ACK perdido, deduplicação,
   resultado incerto e tombstone após release.
7. Isolamento Lua, callback nativo bloqueado, duas sessões no mesmo alvo,
   troca de save, estabilidade real versus best-effort e quotas agregadas.

As etapas, limites iniciais e condições para manter uma capacidade
indisponível são normativos na Spec 0014. Uma dependência de Lua para gameplay
precisa ser comprovada por perfil, não presumida nem exigida para toda build.

## Referências

- [Spec 0013](../specs/0013-debug-bridge-injection.md)
- [Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md)
- [Threat model](../threat-model/runtime-memory-debug.md)
- [Microsoft Detours](https://github.com/microsoft/Detours)
