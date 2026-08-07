---
name: cpp-interop
description: Interop nativo para o projeto Argos Runtime Memory MCP.
---

# Interop nativo

Isole Win32, Linux, C e outras ABIs na infraestrutura. Defina ownership de handles, encoding UTF-8, alinhamento, tamanhos, exceções e códigos de erro nas fronteiras. Exceções não atravessam C callbacks ou módulos incompatíveis. Conversões nativas devem produzir erros tipados e seguros.

## Processo obrigatório

1. Ler arquitetura, ADRs e threat model relevantes.
2. Declarar invariantes, ownership e política de erros.
3. Implementar a menor mudança coerente com as camadas.
4. Adicionar testes e casos de falha.
5. Compilar com warnings elevados e executar sanitizers aplicáveis.
6. Atualizar documentação e registrar trade-offs.

## Definition of Done

- C++23 explícito;
- sem warnings novos;
- ownership e lifetime claros;
- sem `new`/`delete` direto sem justificativa;
- testes unitários e de contrato passando;
- erros externos traduzidos para mensagens seguras;
- sem segredos em logs;
- revisão arquitetural e de segurança concluída.
