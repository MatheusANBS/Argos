# Revisão — inventário de recursos Santa Monica (ADR-0028)

Data: 2026-09-13. Escopo: domínio `santa_monica_inventory`, reader
`santa_monica_inventory_reader`, 16º campo do perfil, serviço, duas tools MCP,
testes e documentação. Revisão feita com as skills obrigatórias do repositório
(arquitetura, C++ moderno, API, memória, build, toolchain, testes, segurança,
observabilidade, revisão) e as de estruturas de dados, concorrência e interop.

## Ponto de partida

Uma sessão anterior deixou o inventário pela metade: domínio, reader e
declarações existiam, sem parser, serviço, tools ou testes. O desenho dependia
de PID e endereço absoluto do array de saldo na configuração do operador. Três
defeitos foram encontrados antes de qualquer uso:

1. **Validação ASCII.** A build real tem dois nomes técnicos UTF-8; o validador
   rejeitaria o inventário inteiro. Substituído por validação UTF-8 bem formada
   sem controles.
2. **Raiz frágil.** Endereço de heap não sobrevive a reinício. A raiz passou a
   ser uma global endereçada por instruções do jogo (`RVA 0x502A4B0`). Um
   candidato mais óbvio, `RVA 0x14261C0`, foi descartado porque nenhuma
   instrução o referencia.
3. **Igualdade de saldos entre passadas.** Com o jogo em andamento, quantidades
   mudam entre as duas leituras, e a tool falharia de forma intermitente. A
   igualdade agora é só estrutural; quantidades vêm da segunda passada.

## Achados e decisões desta revisão

- **Alinhamento do registro.** A primeira hipótese ancorava a entrada 0x28 bytes
  depois do início real. O disassembly (`[conjunto+0x10] + idx<<6`) fixou o
  registro no cabeçalho do store; o layout do código segue o jogo.
- **Escrita em recurso nunca adquirido.** Estado `2` com quantidade `-1` tem
  correlação perfeita nas 1.676 entradas. Gravar só a quantidade deixaria tag,
  ordem de aquisição e flags incoerentes; a escrita é recusada
  (`resource_not_acquired`).
- **TOCTOU.** Ligação e estado são relidos imediatamente antes da escrita e a
  quantidade é relida depois. A corrida com a thread do jogo continua possível e
  está declarada (`engine_transaction: false`).
- **Concorrência.** O cache do snapshot fica atrás de um mutex que protege só a
  troca de ponteiro e o contador de geração; nenhuma leitura de processo ocorre
  com lock. A escrita invalida o cache mesmo quando falha.
- **Exposição.** Nenhuma resposta ou log contém endereço; erros usam razões
  fixas. O cliente não fornece endereço, offset nem bytes para a escrita.
- **Regressão introduzida e corrigida durante a revisão.** Ao corrigir o warning
  `C4456` (variável `page` sombreada no teste de contrato), duas referências
  ficaram apontando para a variável externa; o teste falhou em dev e ASan e foi
  corrigido. O warning e a falha foram ambos eliminados.

## Verificação

- `cmake --build --preset dev` e `--preset asan`: sem warnings novos. O único
  warning restante, `C4996` (`getenv`) em `src/security/policy.cpp`, é
  pré-existente.
- `ctest --preset dev`: 10/10. `ctest --preset asan`: 10/10, incluindo
  `argos_santa_monica_inventory_tests` e os fluxos de recursos do contrato.
- Instalação autorizada, sessão viva do operador: leitura das 1.676 entradas em
  0,67 s com quantidades iguais à leitura direta; escrita idempotente verificada;
  recusas reais de sessão somente leitura, recurso nunca adquirido, teto, frase
  ausente e nome inexistente.

## Riscos residuais e pendências

- Layout inferido por correlação e confirmado por disassembly nesta build, sem
  símbolo; outra build exige novo perfil.
- Texto localizado não é resolvido: não há raiz comprovada para o índice id→texto.
- Concessão nativa, remoção, SLI invocável e Lua não existem. Exigem dispatcher
  na thread do jogo, bootstrap de segredo sem stdin, hooks seguros e validação em
  alvo controlado antes de qualquer injeção no processo do operador.
- Nenhum achado crítico ou alto em aberto nesta superfície.
