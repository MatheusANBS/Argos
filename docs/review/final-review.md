# Revisão final — 0.1.0

Data: 2026-08-05

## Resultado

A implementação foi revisada quanto a arquitetura, ownership, segurança de memória, limites, protocolo, cancelamento, shutdown, logs e testes.

## Verificações executadas

| Verificação | Resultado |
|---|---|
| GCC 14.2 Debug | passou sem warnings |
| GCC 14.2 Release | passou sem warnings |
| Clang 17 Debug | passou sem warnings |
| Testes unitários | passaram |
| Testes de contrato MCP | passaram |
| ASan + UBSan | passaram |
| Smoke test JSON-RPC stdio | passou |
| Separação stdout/stderr | confirmada |
| Escrita desabilitada por padrão | confirmada |
| Cancelamento cooperativo de scan | testado |

## Limitações de validação

O ambiente de execução não possui MSVC nem cross-compiler MinGW. O código Win32 foi implementado atrás de fronteira de plataforma, mas não foi compilado neste ambiente. A validação em Windows deve executar `cmake --preset dev`, build, testes e smoke test antes de publicação binária.

O acesso real a processos Linux pode ser bloqueado por `ptrace_scope`, sandbox ou namespaces. Os testes de comportamento usam provider falso para serem determinísticos; as chamadas nativas são exercitadas pelo build e pelo process listing do smoke test.

## Escopo deliberadamente excluído

- breakpoints e single-step;
- suspensão e retomada de threads;
- alteração de proteção de páginas;
- injeção de código ou bibliotecas;
- criação de thread remota;
- evasão de EDR/anticheat;
- captura de credenciais;
- transporte HTTP.
