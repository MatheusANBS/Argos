# ADR-0029 — Desmontador nativo e referências de código (xrefs)

Status: aceito e implementado (decodificação x86/x64 somente leitura e varredura
de referências de código). Nenhuma escrita, hook ou invocação é introduzida aqui.

## Contexto

A inspeção atual materializa dados já presentes no processo: regiões, módulos,
ponteiros, candidatos a objeto/vtable ([ADR-0009](0009-address-inspection.md)) e
scans de valor. Falta o passo que transforma *endereços* em *comportamento*: qual
instrução lê ou escreve um slot, qual função contém um endereço, para onde um
`call`/`jmp` desvia. Sem isso, achar o atributo de um item equipado depende de
rodadas repetidas de scan por diferença, e a bridge futura ([ADR-0021](0021-opt-in-debug-bridge-injection.md))
não tem como saber *onde* instalar um hook.

Um desmontador responde exatamente isso, e é uma capacidade **somente leitura**:
decodifica bytes que a sessão já pode ler. Não escreve no alvo, não injeta, não
executa código. Por isso compartilha a superfície de autorização das demais tools
de leitura (`inspect_address`, `strings`) e **não** recebe um gate de ambiente
próprio — quem pode ler a memória já pode desmontá-la.

## Decisão

### Dependência: Zydis (vendorizado)

A decodificação x86/x64 é delegada ao [Zydis](https://github.com/zyantific/zydis)
v4.1.1 (com Zycore `0b2432c`), licença MIT, vendorizado em `third_party/zydis`
(fontes completas, submódulo resolvido e fixado). Escrever um decodificador x86-64
completo e correto neste repositório seria maior e mais arriscado que a própria
feature; Zydis é uma biblioteca C madura, sem dependências transitivas, que se
compila como alvo estático via `add_subdirectory`. A integração:

- compila apenas a biblioteca `Zydis` (exemplos, ferramentas, testes e Doxygen do
  upstream ficam desligados); o alvo estático define `ZYDIS_STATIC_BUILD`;
- fica isolada atrás da porta de domínio `Disassembler`: Zydis é um detalhe de
  `infrastructure`, e nenhum tipo de Zydis atravessa a API de domínio/MCP;
- atualização acompanha a tag upstream; a origem, versão e hash ficam registrados
  nesta ADR e no README.

### Porta de domínio

`domain::Disassembler` decodifica **uma** instrução a partir de um buffer e de um
endereço de runtime, devolvendo `DecodedInstruction` tipada: endereço, tamanho,
mnemônico, texto formatado opcional e as *referências resolvidas* da instrução
(alvo absoluto de branch/call e operandos de memória RIP-relativos), cada uma com
sua natureza (`branch`, `call`, `memory_read`, `memory_write`, `memory`). O
domínio não conhece Zydis, opcode, ABI nem bytes de transporte. A resolução de
endereço absoluto (RIP-relativo e deslocamento de branch) é feita na
infraestrutura, porque depende do decodificador; o domínio e a aplicação operam
só sobre os tipos resolvidos.

### Tools MCP (somente leitura)

| Tool | Contrato |
|---|---|
| `memory_debug_disassemble` | Decodifica a partir de um endereço por contagem de instruções (e teto de bytes), devolvendo a lista com mnemônico, texto, bytes e alvos resolvidos. |
| `memory_debug_find_code_references` | Varre um intervalo (ou módulo) executável decodificando linearmente e devolve as instruções cujo alvo resolvido cai em `target_address` (ou numa janela em torno dele), com orçamento de bytes e teto de resultados. |

Ambas leem pela sessão existente, respeitam os limites da policy e não aceitam do
cliente endereço de função, RVA de hook, DLL nem payload. `find_code_references`
é a tool que localiza "quem lê/escreve este slot" e "quem chama esta função" — a
base para a engenharia reversa por build exigida antes de qualquer hook.

A varredura linear de `.text` pode decodificar instruções desalinhadas em preenchimento
entre funções; por isso cada hit declara que é evidência de referência, não prova
de limite de função. Instruções que não decodificam são puladas por um byte, sem
abortar a varredura. Tetos de bytes e de resultados são da policy e só podem ser
reduzidos pela requisição.

### Limites (policy)

`max_disassemble_instructions` (4096), `max_code_ref_byte_budget` (64 MiB, limitado
ao teto de scan) e `max_code_ref_results` (4096). Validados antes de qualquer
leitura; a requisição só estreita.

## Consequências

- o agente passa a correlacionar endereços com o código que os usa, sem rodadas
  repetidas de scan por diferença, e a bridge futura ganha um meio de localizar
  pontos de hook por evidência estática;
- surge uma dependência vendorizada (Zydis/Zycore), isolada na infraestrutura e
  fixada por versão;
- a capacidade permanece somente leitura: nenhuma escrita, hook, breakpoint ou
  execução é introduzida aqui;
- varredura linear não reconstrói CFG nem limites exatos de função; isso é
  evidência de referência, e hits em preenchimento são possíveis e declarados.

## Verificação

- Testes de domínio/infra decodificam bytes x64 conhecidos pelo Zydis real
  (como os testes de bridge chamam a CNG real): comprimento, mnemônico e alvo
  absoluto de um `call rel32`, de um `lea`/`mov` RIP-relativo e de um `jmp`.
- Testes de aplicação com a sessão esparsa: `disassemble` respeita contagem e
  tetos; `find_code_references` acha a instrução que referencia um alvo plantado,
  respeita orçamento e teto, pula bytes indecodificáveis e não lê fora do
  intervalo.
- Contrato MCP: schemas, campos ausentes/inválidos, tetos e redação de erros.
- Build MSVC com warnings elevados e testes/sanitizers aplicáveis antes de a ADR
  passar a implementado.

Referências: [ADR-0009](0009-address-inspection.md),
[ADR-0021](0021-opt-in-debug-bridge-injection.md).
