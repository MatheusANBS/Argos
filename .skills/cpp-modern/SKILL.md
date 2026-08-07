---
name: cpp-modern
description: C++ moderno e seguro para o projeto Argos Runtime Memory MCP.
---

# C++ moderno e seguro

Use C++23, RAII, const-correctness, [[nodiscard]], noexcept contratual, tipos fortes, std::span, std::string_view, std::filesystem::path, ranges e algoritmos padrão. Prefira valor, referência e unique_ptr; use shared_ptr somente quando o ownership realmente for compartilhado.

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
