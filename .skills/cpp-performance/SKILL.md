---
name: cpp-performance
description: Performance mensurável para o projeto Argos Runtime Memory MCP.
---

# Performance mensurável

Meça antes de otimizar. Para scans, parsing e serialização, registre baseline, latência, throughput, alocações, memória e ambiente. Favoreça processamento em chunks, buffers reutilizados e estruturas contíguas. Não troque correção ou limites de segurança por ganho não comprovado.

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
