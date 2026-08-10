# ADR-0016 — Compatibilidade MCP dual-era 2026-07-28

Status: aceito

## Contexto

O MCP `2026-07-28` substitui a negociação de sessão por descoberta e
metadados repetidos em cada requisição. Clientes `2025-11-25` e
`2025-06-18`, porém, ainda dependem do ciclo `initialize` +
`notifications/initialized`, de `ping` e do formato antigo dos resultados.
Como o transporte `stdio` pode ser iniciado por clientes de qualquer uma das
eras, trocar um contrato pelo outro quebraria integrações existentes.

Além da interoperabilidade, serializar o mesmo resultado de ferramenta como
`TextContent` e `structuredContent` dobra o volume dominante de respostas
grandes e obriga o servidor a percorrer a árvore JSON uma vez a mais. O novo
contrato permite que clientes modernos consumam diretamente o conteúdo
estruturado.

## Decisão

O servidor oferece os protocolos, nesta ordem de preferência:

1. `2026-07-28`;
2. `2025-11-25`;
3. `2025-06-18`.

Uma requisição entra no caminho moderno somente quando
`params._meta["io.modelcontextprotocol/protocolVersion"]` está presente. A
decisão é local à requisição: não há estado de protocolo inferido de chamadas
anteriores. Nesse caminho, a versão deve ser exatamente `2026-07-28` e
`params._meta["io.modelcontextprotocol/clientCapabilities"]` deve ser um
objeto. `clientInfo` é opcional, mas deve ser objeto quando presente.
Metadados modernos sem `protocolVersion` são rejeitados, em vez de caírem
silenciosamente no caminho legado. Uma versão diferente retorna JSON-RPC
`-32022`, com
`data.supported` e `data.requested`; capacidades ausentes ou de outro tipo
retornam `-32602`.

`server/discover` existe somente no caminho moderno e informa:

- `supportedVersions` com as três versões acima;
- capacidade `tools`;
- instruções operacionais;
- `ttlMs = 300000` e `cacheScope = "public"`;
- identidade do servidor em
  `_meta["io.modelcontextprotocol/serverInfo"]`.

O escopo `public` significa compartilhável entre clientes do mesmo processo
servidor: o catálogo é imutável durante a vida da instância e não contém
dados do processo-alvo nem do usuário. O TTL finito de cinco minutos limita a
persistência de um catálogo após a substituição do binário ou da configuração.

Todo resultado bem-sucedido moderno recebe `resultType = "complete"` e a
identidade do servidor no mesmo campo reservado de `_meta`. `tools/list`
também recebe as dicas de cache e usa um catálogo imutável construído e
ordenado uma vez por instância, tornando a resposta determinística e amigável
a caches. Cada tool anuncia um `outputSchema` para o envelope estruturado.

Em `tools/call`, o caminho moderno devolve o resultado em
`structuredContent` e um array `content` vazio. Ele não gera uma segunda
cópia textual do JSON. O caminho legado continua devolvendo o JSON serializado
como um único `TextContent`, além de `structuredContent`, para preservar
clientes existentes; depois da serialização, a árvore estruturada é movida
para o envelope em vez de copiada.

Tool inexistente é erro de protocolo JSON-RPC `-32602`; erros acionáveis de uma
execução válida continuam em `isError: true`. `initialize`, `ping` e os envelopes antigos permanecem inalterados quando o
metadado moderno não está presente. `initialize` e `ping` modernos retornam
`-32601`, pois não fazem parte do ciclo de vida sem estado. Uma notificação de
cancelamento é linearizada com a conclusão: se observada primeiro, pede stop e
suprime qualquer resposta posterior que carregaria o ID cancelado.

## Consequências

- clientes das três versões podem usar o mesmo executável sem ambiguidade de
  estado entre requisições;
- respostas modernas de ferramentas grandes deixam de pagar a serialização e
  o tráfego de uma cópia textual redundante;
- descoberta e catálogo modernos podem ser reutilizados com segurança por
  cinco minutos e têm representação determinística;
- clientes legados mantêm negociação, `ping`, conteúdo textual e estrutura de
  resposta anteriores;
- toda nova resposta moderna deve passar pelo construtor comum do envelope,
  para não omitir `resultType` nem a identidade reservada;
- aumentar o paralelismo de `tools/call` continua sendo uma decisão separada.

## Verificação de contrato

Os testes exercitam as duas eras no mesmo `Server`, incluindo inicialização
`2025-11-25`/`2025-06-18`, descoberta moderna, ordem do catálogo, dicas de
cache, metadados obrigatórios, versão desconhecida, cancelamento, tool
inexistente e ausência de
`TextContent` redundante em chamadas modernas. Também verificam explicitamente
que uma chamada legada ainda contém a representação textual compatível.

## Referências

- [MCP 2026-07-28](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Server discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Transporte stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
