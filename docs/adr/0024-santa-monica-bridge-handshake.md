# ADR-0024 — Handshake autenticado do canal Santa Monica

Status: aceito e implementado como núcleo de verificação no domínio, primitiva
HMAC-SHA-256 e enquadramento na infraestrutura, sem transporte instalado.

## Decisão

O canal da bridge usa autenticação mútua por desafio-resposta sobre um segredo
efêmero de sessão, entregue por canal de bootstrap protegido — nunca em
argumentos, variáveis públicas, nome de pipe ou logs. Possuir o segredo é o
que autentica; campo declarado, PID, nome de pipe ou versão anunciada não
autenticam nada por si.

O domínio possui as regras de vínculo e verificação (`BridgeHandshakeServer`,
transcript canônico, comparação em tempo constante, `BridgeSecret` com
zeroização). A infraestrutura possui a primitiva e a aleatoriedade. O domínio
não conhece CNG, bytes de transporte nem relógio: deadlines e I/O pertencem à
camada que opera o canal.

### Primitiva

HMAC-SHA-256 e nonces de 32 bytes vêm do provedor do sistema (Windows CNG:
`BCryptOpenAlgorithmProvider` com `BCRYPT_ALG_HANDLE_HMAC_FLAG`,
`BCryptGenRandom` com `BCRYPT_USE_SYSTEM_PREFERRED_RNG`). `bcrypt.lib` é
biblioteca do sistema, na mesma classe de `advapi32`/`dbghelp` já usadas; não
há dependência externa nova, vendorização nem primitiva criptográfica escrita
neste repositório. Onde o provedor não existe, a fábrica retorna `unsupported`
e o handshake fica indisponível — nunca há fallback para primitiva própria ou
para aceitar o peer sem prova.

O segredo tem 32 a 64 bytes, vive em armazenamento fixo (sem realocação que
deixe cópias), é apagado na destruição e no move, e nunca entra em transcript,
erro, log ou campo de wire.

### Transcript

O MAC cobre um transcript canônico, com separação de domínio por rótulo:

| Ordem | Campo |
|---|---|
| 1 | rótulo (u32 de comprimento + ASCII) |
| 2 | protocol version u32 |
| 3 | bridge version u32 |
| 4 | capacidades u64 |
| 5 | nonce do servidor (32 bytes) |
| 6 | nonce da bridge (32 bytes) |
| 7 | digest do perfil (32 bytes) |
| 8 | digest da bridge (32 bytes) |
| 9 | instância de processo (u32 + ASCII) |
| 10 | época da bridge (u32 + ASCII) |
| 11 | request ID u64 |

Rótulos: `argos-santamonica-bridge-attest-v1` para a prova da bridge e
`argos-santamonica-server-accept-v1` para a do servidor. Uma prova nunca serve
para a outra direção, para outro par de nonces nem para outra sessão.

### Fluxo

1. `hello` (servidor → bridge): versão, request ID, nonce fresco do CSPRNG e
   capacidades oferecidas.
2. `attest` (bridge → servidor): nonce próprio, identidade declarada
   (versões, digests, instância de processo, época), capacidades solicitadas e
   tag sobre o transcript de attest.
3. `accept` (servidor → bridge): capacidades concedidas e tag sobre o
   transcript de accept. A bridge verifica antes de aceitar comandos.

O servidor valida estrutura (nonce não nulo e diferente do seu, capacidades
dentro do conjunto fechado e do oferecido), **depois** verifica a tag e só
então compara a identidade declarada com a esperada, respondendo
`identity_mismatch` sem dizer qual campo divergiu. Assim, nenhum peer sem o
segredo obtém oráculo sobre a identidade esperada.

Capacidades são um bitmask fechado; concedido é sempre subconjunto do
oferecido e do solicitado, e a tag de accept cobre o conjunto concedido, então
a bridge não pode alegar mais do que recebeu. Esta versão define apenas
`reflection_read`; Lua, gameplay e invocação exigem ADR e provas próprias.

O objeto de handshake é de uso único: sucesso fecha a negociação e qualquer
falha o invalida definitivamente. Um novo handshake exige nova sessão, novo
segredo e novo nonce. Uma chamada duplicada depois de estabelecido é recusada
como `handshake_state`, mas nunca derruba uma negociação já concluída.

### Enquadramento

Os frames usam a mesma disciplina de header da ADR-0023, com magic `SMBH` e
32 bytes: magic, versão u16, comprimento do header u16, kind u16, reservado
u16 zero, comprimento do payload u32, request ID u64 e sequência u64. Kinds:
`hello` 1, `attest` 2, `accept` 3, `reject` 4. O caminho feliz usa sequência
1, 2 e 3; um `reject` ocupa a posição da resposta que substitui. Frame completo
tem no máximo 4 KiB e o header é a única fonte do request ID — o payload de
`hello` não o repete.

| Kind | Payload |
|---|---|
| hello | protocol version u32, nonce do servidor (32), capacidades oferecidas u64 |
| attest | protocol version u32, bridge version u32, nonce da bridge (32), digest do perfil (32), digest da bridge (32), instância de processo, época, capacidades solicitadas u64, tag (32) |
| accept | capacidades concedidas u64, tag (32) |
| reject | motivo u16 do conjunto fechado |

O decoder rejeita magic, versão, comprimento de header, reservado, kind,
request, sequência, motivo de reject e comprimentos inválidos; exige o frame
exato, sem bytes faltantes nem excedentes, e recusa payload residual. Strings
são ASCII imprimível de até 128 bytes. O codec não autentica, não guarda
segredo e não decide semântica: quem verifica é o domínio.

## Limites e fronteira de confiança

Este incremento entrega regras e primitiva, **não** transporte. Named pipe,
ACL restrita ao usuário autorizado, recusa de acesso remoto, canal de
bootstrap, validação da imagem carregada, heartbeat, fila e dispatcher
permanecem pendentes. Enquanto isso, nenhuma tool MCP é habilitada.

Frescor do nonce e unicidade do segredo por sessão impedem replay entre
handshakes; dentro de uma conexão, sequência e request ID continuam a cargo do
enquadramento. O modelo não protege contra alvo já comprometido, contra quem
obtenha o segredo por bootstrap inseguro, nem contra um agente com acesso de
depuração equivalente ao alvo. A tag prova posse do segredo, não que a imagem
carregada corresponde ao artefato aprovado — essa validação é requisito
separado.

## Verificação

Executado em `argos_santa_monica_bridge_tests`: transcript determinístico,
byte a byte igual à forma canônica acima e sensível a cada campo vinculado
(nenhuma variação colide com outra); tag válida aceita; segredo errado, rótulo
trocado, nonce trocado ou espelhado, capacidade inflada depois de assinada,
versão alterada depois de assinada e tag adulterada recusados como
`invalid_tag`; identidade divergente recusada como `identity_mismatch` somente
após a prova; comparação sem saída antecipada; binding, oferta, CSPRNG
indisponível e nonce degenerado recusados antes de qualquer uso; ordem e uso
único do estado; attestation de outro handshake recusada; zeroização do
segredo verificada no armazenamento do objeto após a destruição.

Nenhum vetor publicado de HMAC-SHA-256 usa chave dentro do piso de 32 bytes
adotado aqui, então a primitiva é verificada de duas formas independentes: o
SHA-256 do provedor é comparado ao valor publicado de `"abc"`, e o HMAC do
provedor é comparado à construção RFC 2104 (ipad/opad) montada sobre esse
mesmo hash, para chaves de 32, 48 e 64 bytes. Também são testados
determinismo, sensibilidade a um bit da chave e da mensagem, mensagem vazia,
nonces distintos e não nulos, e um handshake completo com a primitiva real.

O enquadramento tem bytes conferidos contra a tabela acima para os quatro
kinds, round-trip de todos, e recusa de magic, versão, comprimento de header,
kind desconhecido, reservado, request, sequência, frame acima do teto, header
curto, frame truncado, bytes excedentes, payload residual, motivo de reject
desconhecido e strings vazias, longas ou não imprimíveis.

Referências: [ADR-0022](0022-santa-monica-kinetica-runtime-instrumentation.md),
[ADR-0023](0023-santa-monica-reflection-stream.md),
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).
