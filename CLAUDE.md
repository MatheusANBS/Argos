# Argos Runtime Memory MCP — regras para agentes

Antes de alterar código C++, leia as skills locais aplicáveis em `.codex/skills/<skill>/SKILL.md`.

Para qualquer alteração neste repositório, são obrigatórias:

1. `cpp-architecture`
2. `cpp-modern`
3. `cpp-api-design`
4. `cpp-memory-safety`
5. `cpp-build-system`
6. `cpp-toolchain`
7. `cpp-testing`
8. `cpp-security`
9. `cpp-observability`
10. `cpp-review`

Use adicionalmente:

- `cpp-data-structures` para coleções, índices, scans e caches;
- `cpp-concurrency` para sessões concorrentes, workers ou cancelamento;
- `cpp-performance` para scan, parsing e serialização;
- `cpp-dependency-management` antes de adicionar biblioteca externa;
- `cpp-interop` ao tocar APIs Win32, Linux, C ou outras fronteiras de linguagem.

## Sequência obrigatória

1. Defina a mudança arquitetural e os contratos.
2. Registre ADR quando houver decisão estrutural, protocolo, dependência ou alteração de segurança.
3. Implemente mantendo domínio independente de MCP/JSON/OS.
4. Adicione ou atualize testes.
5. Compile com warnings elevados.
6. Execute testes normais e sanitizers aplicáveis.
7. Revise segurança, lifetime, concorrência, shutdown e exposição de dados.
8. Atualize README, documentação da API e threat model quando necessário.

## Restrições de segurança

Não adicionar:

- injeção de código ou DLL;
- criação de thread remota;
- bypass de anticheat, EDR ou proteção do sistema;
- ocultação de processo, handle ou atividade;
- captura de credenciais, tokens ou segredos;
- elevação de privilégio;
- escrita habilitada por padrão;
- comandos shell montados com entrada externa.

`stdout` deve conter exclusivamente JSON-RPC/MCP. Logs ficam em `stderr`.
