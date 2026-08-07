# Changelog

## 0.1.0 — 2026-08-05

- servidor MCP `stdio` compatível com `2025-11-25`;
- parser e serializador JSON internos;
- providers nativos para Windows e Linux;
- sessions explícitas com RAII;
- process list, attach, detach, sessions, regions e modules;
- read, read batch, typed read, exact scan e pointer chain;
- write gate desabilitado por padrão;
- cancelamento cooperativo de scans via `notifications/cancelled`;
- logs estruturados em `stderr`;
- skills C++ instaladas em `.codex/skills`;
- testes unitários, contrato MCP, presets de sanitizer e documentação de segurança.
