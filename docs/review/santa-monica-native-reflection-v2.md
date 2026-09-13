# Revisão — continuação do reader nativo Santa Monica

## Entrega

Concluída a expansão interrompida de `NativeTypeTableReader`, integrada ao
parser de perfil, aplicação e às seis tools MCP existentes. Decisão e migração
na [ADR-0027](../adr/0027-santa-monica-native-reflection.md).

- Família v2 com TypeDecl ancorado corretamente, herança e faixa própria de
  atributos; cópias herdadas e views embutidas não duplicam campos.
- Enums homônimos usam índices distintos; valores u64 continuam decimais exatos.
- Funções SLI são descritivas; o perfil separa as 309 funções das 86 propriedades.
- Ponteiros/coleções podem ter conteúdo sem tipo refletido. Objetos embutidos
  continuam exigindo tipo e tamanho exatos; campos sem tamanho não são inventados.
- Perfil com nove ou quinze campos; todos os RVAs e o digest do módulo entram
  na identidade canônica. A família antiga é recusada para evitar migração parcial.

## Segurança, lifetime e limites

Cada leitura fica dentro da imagem; arrays de enum são validados integralmente
antes de acesso, inclusive overflow. Strings ficam na janela do perfil. Nada
segue `m_Members` no heap e callbacks nunca são executados. Não há handles ou
threads novos: reader e índices são locais, com RuntimeMemoryView emprestado.
Falhas de I/O, cancelamento e deadline invalidam a instância; o catálogo não é
publicado em erro. Preload respeita teto de slots e memória antes da alocação;
há teto de 64 MiB lidos e deadline cooperativo de até 5 s.

Nenhuma alteração de escrita, política de autorização, configuração persistente
ou instalação foi feita nesta continuação. Alterações anteriores nesses arquivos
foram preservadas. `stdout` do servidor continua exclusivamente JSON-RPC.
Sem novos achados altos/críticos identificados na revisão desta continuação;
isso não equivale a uma auditoria de todas as alterações anteriores da árvore.

## Validação

- MSVC/C++23, `/W4 /permissive-`: builds dev e ASan concluídas.
- CTest: **9/9 dev** e **9/9 ASan**, incluindo contrato MCP nativo com fixture
  própria, parser estendido e negativos de bounds, referências, cancelamento,
  I/O, prazo, duplicatas, tipos primitivos e índices temporários.
- Sem warnings novos; C4996 de `getenv` em `policy.cpp` já existia.
- Este preset MSVC instrumenta AddressSanitizer; não executa UBSan/TSan.
- Smoke pelo executável MCP no processo já aberto, com escrita desabilitada e
  sessão `read_only`: 1.192 tipos, 7.041 campos, 482 enums, 3.791 valores e
  309 funções. Consultas de tipo/herança, enums e SLI, release e detach passaram.
  Métrica e faixas constam na [evidência](../engines/gow2018-steam-11168363-evidence.md).

## Pendências delimitadas

Auxiliares de arrays/mapas, mapas sem tamanho comprovado, propriedades SLI e
os seis slots de tipo rejeitados conservadoramente ainda limitam cobertura.
O resultado permanece `validated_best_effort` e `coverage_complete: false`.
Atestação da imagem, bridge no jogo, dispatcher, inventário, gameplay e Lua
exigem os próximos incrementos. O binário instalado e o perfil persistente
do cliente não foram migrados nesta rodada. As alterações estão sem commit.
