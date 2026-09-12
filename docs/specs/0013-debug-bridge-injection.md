# Spec 0013 — `memory_debug.debug_bridge_inject`

Status: implementado (Windows)

## Contrato

`memory_debug.debug_bridge_inject` carrega uma bridge de depuração Argos
previamente aprovada em uma sessão autorizada. A operação não recebe código,
exports, argumentos arbitrários ou bytes de payload.

### Request

```json
{
  "session_id": "opaque-session-id",
  "bridge_path": "C:\\Argos\\bin\\argos_debug_bridge.dll",
  "authorized": true
}
```

### Response

```json
{
  "ok": true,
  "data": {
    "pid": 1234,
    "bridge_name": "argos_debug_bridge.dll",
    "module_base": "0x7FF700000000"
  }
}
```

## Invariantes

- o gate de ambiente e a allowlist são avaliados no startup; a request nunca
  habilita capacidade;
- `bridge_path` é absoluto, UTF-8 válido, aponta a arquivo regular e, após
  canonicalização, pertence à allowlist;
- toda falha antes da chamada nativa não cria handle ou memória remota;
- handles nativos e alocação temporária remota são RAII e são liberados em
  todos os ramos de erro;
- somente o loader do sistema recebe o caminho da DLL aprovada; não há shell,
  arquivo temporário, mudança de proteção de página ou execução de payload;
- resultado é factual: base só é retornada após o carregamento ter concluído
  e o módulo constar no snapshot do alvo.
