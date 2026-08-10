# Roadmap — Introspecção de runtime sem código-fonte

Status: aceito

## Motivação

Durante uma sessão real de teste do MCP contra `argos_debug_target_game.exe`
(sem ler `tools/debug_target_game.cpp`), cinco lacunas concretas tornaram a
tarefa "encontrar classes e offsets" muito mais lenta do que deveria:

1. Não há como capturar a saída do processo-alvo. O binário de teste imprime
   os próprios endereços de `GameState`, `Player`, `Pattern` e o comando
   `scan_exact` correto no `stdout` — informação inacessível porque o MCP só
   anexa a processos já em execução.
2. `memory_debug.read` devolve bytes crus em hex. Para extrair nomes de
   campos foi preciso ler um módulo inteiro, estourar o limite de tokens do
   cliente, salvar em arquivo e escrever um script externo de extração de
   strings.
3. `memory_debug.pdb_type` exige o nome exato do tipo. Sem enumeração, só é
   possível consultar tipos cujo nome já é conhecido por outra via.
4. Não existe scan incremental (estilo Cheat Engine). `scan_exact` só
   encontra um padrão de bytes já conhecido; não há como isolar o offset de
   um campo dinâmico (HP, posição, score) apenas observando variação de
   valor entre duas leituras.
5. Não existe scan reverso de ponteiro. Encontrar quem referencia um
   endereço exige codificar o endereço manualmente em hex little-endian e
   reaproveitar `scan_exact` "na unha".

Este roadmap define, em ordem de implementação recomendada, as specs e ADRs
que fecham essas lacunas. Cada item individual continua sujeito à sequência
obrigatória do `AGENTS.md` (ADR → contrato → implementação → testes →
compilação com warnings elevados → sanitizers → revisão de segurança →
documentação) e às skills `.skills/cpp-*` aplicáveis.

## Itens

| # | Spec | ADR | Gate novo? | Risco | Generaliza para jogos reais? |
|---|------|-----|------------|-------|-------------------------------|
| 1 | [0001-memory-strings](0001-memory-strings.md) | [ADR-0006](../adr/0006-memory-string-extraction.md) | não | baixo | sim |
| 2 | [0002-pointer-scan](0002-pointer-scan.md) | [ADR-0007](../adr/0007-reverse-pointer-scan.md) | não | baixo | sim |
| 3 | [0003-pdb-type-catalog](0003-pdb-type-catalog.md) | [ADR-0008](../adr/0008-pdb-type-catalog-enumeration.md) | não | baixo | sim (quando há PDB) |
| 4 | [0004-value-diff-scan](0004-value-diff-scan.md) | [ADR-0009](../adr/0009-value-diff-scan-sessions.md) | não (limites novos) | médio | sim |
| 5 | [0005-managed-process-launch](0005-managed-process-launch.md) | [ADR-0010](../adr/0010-managed-process-launch.md) | sim (`ARGOS_MCP_ALLOW_LAUNCH`) | alto | não — só útil para alvos de teste que o operador controla |

## Por que esta ordem

O valor "maior" percebido durante a sessão foi capturar `stdout` do alvo
(item 5), porque o binário de teste literalmente entrega a resposta pronta.
Mas essa observação é enganosa como critério de priorização: `debug_target_game`
é um alvo cooperativo criado para testar o próprio MCP. Um jogo real de
terceiros já está em execução, não imprime layout de memória, e na maioria
dos casos não fornece PDB. Nesse cenário — o caso de uso dominante do MCP —
os itens 1 a 4 são o que de fato resolve "encontrar classes e offsets sem
código-fonte"; o item 5 só ajuda no fluxo de desenvolvimento/CI deste próprio
repositório.

Os itens 1 a 3 são aditivos, somente-leitura, sem novo gate de ambiente e
reaproveitam limites de `SecurityPolicy` já existentes (`authorize_scan`) —
menor risco, menor esforço, devem vir primeiro. O item 4 introduz um
subsistema de estado novo dentro do processo do MCP (candidatos de scan) e
precisa de limites próprios, mas ainda não muda a superfície de autorização.
O item 5 muda a classe de capacidade do servidor — de "ler processos" para
"criar processos" — e por isso é o único que exige um novo gate de ambiente,
revisão de segurança dedicada e, por padrão, deve permanecer desligado.

## Fora de escopo

- Escrita habilitada por padrão, bypass de proteção, injeção de código,
  criação de thread remota, ocultação de processo/handle ou captura de
  credenciais continuam proibidos, sem exceção, para todos os itens acima
  (ver `AGENTS.md`).
- Suporte a macOS não é alterado por nenhuma destas specs.
