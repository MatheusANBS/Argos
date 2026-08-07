---
name: cpp-build-system
description: CMake moderno para o projeto Argos Runtime Memory MCP.
---

# CMake moderno

Use CMake baseado em targets. Declare cxx_std_23 por target; use target_include_directories, target_link_libraries, target_compile_options e target_compile_definitions. Não use include_directories, link_directories ou add_definitions globalmente. Mantenha presets para dev, release e sanitizers.

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
