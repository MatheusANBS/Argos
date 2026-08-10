# 📝 Guia: Cadastrar Argos MCP no Claude

## ⚡ Resumo Rápido

```powershell
# 1. Compilar
cmake --preset dev
cmake --build --preset dev

# 2. Executar teste (em outro terminal)
.\build\dev\argos_memory_target

# 3. Testar MCP manualmente
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | .\build\dev\argos_runtime_memory_mcp.exe

# 4. Cadastrar no Claude
# Editar: %APPDATA%\Claude\claude_desktop_config.json
```

---

## 🪟 Windows (Detalhado)

### Passo 1: Compilar Executável

```powershell
# PowerShell (Admin não obrigatório)
cd C:\Users\matheuss\Desktop\Sistemas\Argos

# Build em modo desenvolvimento
cmake --preset dev
cmake --build --preset dev

# Validar
if (Test-Path "build\dev\argos_runtime_memory_mcp.exe") {
    Write-Host "✅ Build bem-sucedido!" -ForegroundColor Green
} else {
    Write-Host "❌ Build falhou" -ForegroundColor Red
}
```

### Passo 2: Teste Manual (Opcional, mas Recomendado)

```powershell
# Terminal 1: Executar target (mantém rodando)
.\build\dev\argos_memory_target

# Saída esperada:
# pid=12345 address=0x7FFD12340000 pattern=4152474f532d4d43502d544553542100

# Terminal 2: Testar MCP
$payload = @{
    jsonrpc = "2.0"
    method  = "tools/list"
    id      = 1
} | ConvertTo-Json -Compress

$payload | .\build\dev\argos_runtime_memory_mcp.exe

# Esperado: JSON com lista de tools disponíveis
```

### Passo 3: Encontrar Arquivo de Configuração

```powershell
# Path padrão:
$ConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"

# Verificar se existe
if (Test-Path $ConfigPath) {
    Write-Host "✅ Arquivo encontrado em: $ConfigPath" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Arquivo ainda não existe, será criado..." -ForegroundColor Cyan
}

# Abrir em editor (se quiser editar manualmente)
notepad $ConfigPath
```

### Passo 4: Adicionar MCP ao Arquivo de Config

**Opção A: Método Automático (PowerShell)**

```powershell
$ConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"
$MCPPath = "C:\Users\matheuss\Desktop\Sistemas\Argos\build\dev\argos_runtime_memory_mcp.exe"

# Ler config existente (ou criar vazia)
$config = if (Test-Path $ConfigPath) {
    Get-Content $ConfigPath | ConvertFrom-Json
} else {
    @{ mcpServers = @{} }
}

# Adicionar servidor Argos
$config.mcpServers."argos-memory" = @{
    command = $MCPPath
    args    = @()
    env     = @{
        "ARGOS_MCP_LOG_LEVEL"        = "info"
        "ARGOS_MCP_ALLOW_WRITE"      = "0"
        "ARGOS_MCP_ALLOW_FOREIGN_USER" = "0"
    }
}

# Salvar
$config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath -Encoding UTF8
Write-Host "✅ MCP registrado com sucesso!" -ForegroundColor Green
```

**Opção B: Edição Manual**

1. Abrir `%APPDATA%\Claude\claude_desktop_config.json` (criar se não existir)
2. Cole este conteúdo:

```json
{
  "mcpServers": {
    "argos-memory": {
      "command": "C:\\Users\\matheuss\\Desktop\\Sistemas\\Argos\\build\\dev\\argos_runtime_memory_mcp.exe",
      "args": [],
      "env": {
        "ARGOS_MCP_LOG_LEVEL": "info",
        "ARGOS_MCP_ALLOW_WRITE": "0",
        "ARGOS_MCP_ALLOW_FOREIGN_USER": "0"
      }
    }
  }
}
```

3. Salvar arquivo (Ctrl+S)

### Passo 5: Reiniciar Claude

```powershell
# Fechar Claude completamente
Get-Process "claude*" | Stop-Process -Force

# Aguardar 2 segundos
Start-Sleep -Seconds 2

# Abrir Claude novamente
# Windows: Pressionar Win+Space, digitar "Claude"
# Ou clicar no ícone
```

### Passo 6: Validar Conexão

No Claude Code ou claude.ai:

```
/mcp list
```

Esperado na resposta:
```
argos-memory
  - memory_debug.process_list
  - memory_debug.attach
  - memory_debug.detach
  - memory_debug.sessions
  ... (mais tools)
```

---

## 🐧 Linux

### Passo 1-2: Compilar e Testar

```bash
cd ~/argos

# Build
cmake --preset dev
cmake --build --preset dev

# Teste (Terminal 1)
./build/dev/argos_memory_target &
TARGET_PID=$!

# Teste (Terminal 2)
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  ./build/dev/argos_runtime_memory_mcp

# Limpar
kill $TARGET_PID
```

### Passo 3-4: Registrar no Claude

```bash
# Criar diretório config
mkdir -p ~/.config/Claude

# Criar/editar arquivo
cat > ~/.config/Claude/claude_desktop_config.json << 'EOF'
{
  "mcpServers": {
    "argos-memory": {
      "command": "/home/matheuss/argos/build/dev/argos_runtime_memory_mcp",
      "args": [],
      "env": {
        "ARGOS_MCP_LOG_LEVEL": "info",
        "ARGOS_MCP_ALLOW_WRITE": "0"
      }
    }
  }
}
EOF

chmod 600 ~/.config/Claude/claude_desktop_config.json
```

### Passo 5-6: Reiniciar e Validar

```bash
# Reiniciar Claude (usar Menu ou terminal)
pkill -f claude  # Se usando CLI

# Validar
/path/to/claude /mcp list
```

---

## ⚙️ Variáveis de Ambiente (Configuração Avançada)

Editar o `env` na config para ajustar comportamento:

As mais usadas ao registrar o servidor:

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `ARGOS_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |
| `ARGOS_MCP_ALLOW_WRITE` | `0` | Habilitar escrita em memória (1 ou 0) |
| `ARGOS_MCP_ALLOW_FOREIGN_USER` | `0` | Permitir outros usuários (1 ou 0) |

A lista completa, com todos os limites rígidos, está em
[`README.md`](README.md#variáveis-de-ambiente) — esta tabela é só um recorte.

### Exemplo: Ativar Escrita

```json
{
  "mcpServers": {
    "argos-memory": {
      "command": "...",
      "env": {
        "ARGOS_MCP_ALLOW_WRITE": "1",
        "ARGOS_MCP_LOG_LEVEL": "debug"
      }
    }
  }
}
```

---

## 🧪 Teste Completo (MCP Contract)

Após registrar, validar com testes formais:

```bash
# Compilar testes de contrato
cmake --preset dev -D ARGOS_BUILD_TESTS=ON
cmake --build --preset dev --target argos_contract_tests

# Executar
ctest --preset dev --verbose
```

Esperado: **ALL TESTS PASSED ✓**

---

## 🐛 Troubleshooting

### ❌ "Command not found" ou "Cannot execute"

```powershell
# Windows: Verificar path absoluto
$exe = "C:\Users\matheuss\Desktop\Sistemas\Argos\build\dev\argos_runtime_memory_mcp.exe"
Test-Path $exe
dir $exe  # Deve listar arquivo
```

### ❌ "MCP não aparece em `/mcp list`"

1. Verificar sintaxe JSON
   ```powershell
   Get-Content $env:APPDATA\Claude\claude_desktop_config.json | ConvertFrom-Json
   ```

2. Verificar logs do Claude
   ```powershell
   # Windows - Logs podem estar em:
   $env:LOCALAPPDATA\Claude\logs\
   ```

3. Reiniciar Claude e aguardar 5 segundos

### ❌ "attach: unauthorized"

Esperado! É segurança. Quando usar, passar `authorized: true`:

```python
# Python example
response = call_tool("memory_debug.attach", {
    "pid": 12345,
    "access": "read_only",   # ou "read_write"; "read" é inválido
    "authorized": True
})
```

### ❌ "write access is disabled"

Editar config e mudar `ARGOS_MCP_ALLOW_WRITE` para `1`:

```json
"env": {
  "ARGOS_MCP_ALLOW_WRITE": "1"
}
```

---

## 📊 Verificar Status do MCP

### Listar Sessões Ativas

No Claude:

```
Call tool: memory_debug.sessions
Expected: {"ok": true, "data": [...]}
```

### Ver Logs em Tempo Real

```bash
# Linux/macOS
tail -f ~/.config/Claude/logs/*.log

# Windows
Get-Content $env:LOCALAPPDATA\Claude\logs\* -Tail 50 -Wait
```

---

## ✅ Checklist Final

- [ ] Compilado com sucesso (`./build/dev/argos_runtime_memory_mcp.exe`)
- [ ] Teste manual funcionou (tools/list respondeu)
- [ ] Arquivo de config criado/editado
- [ ] Path absoluto está correto
- [ ] Claude reiniciado
- [ ] `/mcp list` mostra `argos-memory`
- [ ] Testes passam (`ctest --preset dev`)
- [ ] Variáveis de ambiente estão configuradas

---

**Status:** ✅ Pronto para usar  
**Próximo:** Consultar `ANALISE_MCP_OTIMIZACAO.md` para dicas de otimização
