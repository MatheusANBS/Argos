# ADR-0022 — Instrumentação runtime Santa Monica/Kinetica por build

## Status

Proposto.

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
2. **Script**: observação Lua e, no perfil de modding habilitado, execução de
   fonte Lua na VM do jogo.
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

`attach` utiliza a bridge aprovada da Spec 0013 em processo já aberto.
`early_load` inicia um jogo controlado com bridge antes do bootstrap Lua; é
necessário para observar/substituir scripts carregados no início. A técnica de
carga antecipada (por exemplo, proxy DLL em diretório de teste) pertence à
infraestrutura e nunca é escolhida pelo cliente MCP.

### Execução no processo

Lua e gameplay são capacidades de modding deliberadas, desabilitadas por
padrão e protegidas por gates separados. Mesmo habilitadas, a bridge aceita
somente nome de função SLI publicado, argumentos validados pelo RTTI,
identificador de item do catálogo e fonte Lua limitada para a VM validada. Ela
não recebe endereço, RVA, export, DLL, shellcode ou função nativa arbitrária.

Os comandos entram em fila e são executados no tick/main thread definido pelo
perfil; nunca por thread remota que chama diretamente a engine. Cada bridge é
de uma sessão, possui uma operação de gameplay ativa e descarta fila pendente
em release, detach, expiração ou shutdown. A primeira entrega não faz unload
de DLL/hook em processo vivo; esse contrato exige quiescência própria.

### Dependências

Esta ADR não adiciona dependências. O projeto de referência usa Detours. Se
Detours for adotado, uma ADR específica deve registrar versão imutável,
origem, licença MIT, lock, política de atualização, threat model e fallback.
Seu uso permanece restrito à bridge Windows, fora do domínio e da API pública.

## Consequências

- O Argos passa a suportar exploração e modding real por build, não somente
  candidatos de memória.
- `grant_item` pode preservar identidade de instância, equipamento, atributos
  e persistência que uma escrita externa cega não conhece.
- Lua e invocação SLI são uma fronteira de confiança maior que a Spec 0013 e
  serão expostos claramente no startup, respostas e logs.
- Builds sem perfil retornam `unsupported`; plausibilidade não substitui
  validação de build.
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

## Referências

- [Spec 0013](../specs/0013-debug-bridge-injection.md)
- [Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md)
- [Threat model](../threat-model/runtime-memory-debug.md)
- [Microsoft Detours](https://github.com/microsoft/Detours)
