# ADR-0025 — Transporte local do canal Santa Monica

Status: aceito e implementado como canal local, bootstrap do segredo e peer
controlado, sem suporte ao jogo real.

## Decisão

O canal é um named pipe local do Windows, criado pelo servidor antes de
existir peer, com uma única instância e ACL própria:

- `FILE_FLAG_FIRST_PIPE_INSTANCE` — o nome não pode ser pré-criado por outro
  processo; se já existir, a criação falha em vez de reaproveitar.
- `PIPE_REJECT_REMOTE_CLIENTS` — conexão remota é recusada pelo kernel.
- `nMaxInstances = 1` — não há segunda conexão para a mesma descoberta.
- DACL protegida contendo apenas o SID do usuário atual
  (`D:P(A;;GA;;;<sid>)`). A garantia de mesmo usuário vem do kernel na
  abertura, não de uma comparação posterior que já teria perdido a corrida.

O nome inclui 32 hex do CSPRNG. Ele **não** é segredo: quem protege é a ACL.
Depois de conectar, o servidor confere o PID do cliente
(`GetNamedPipeClientProcessId`) contra o processo esperado. Isso vincula a
conexão ao alvo, mas não autentica: a autenticação é o handshake da ADR-0024.

### Bootstrap do segredo

O segredo de 32 bytes vem do CSPRNG do sistema e nunca passa por argv,
variável de ambiente, nome de pipe, arquivo ou log. Para o peer controlado
desta etapa, o servidor o entrega pela **stdin** do processo filho, por pipe
anônimo, e fecha a ponta de escrita em seguida; o filho lê exatamente 32 bytes
antes de qualquer outra coisa. Para uma bridge injetada, o bootstrap
equivalente é a escrita na memória do alvo no momento da injeção; esse caminho
ainda não existe.

O peer é um executável configurado pelo operador (`ARGOS_MCP_SANTAMONICA_PEER`),
nunca um caminho vindo do cliente MCP. O servidor o encerra ao concluir,
falhar ou expirar o deadline, e a destruição do canal cancela I/O pendente.

### I/O

Todo I/O é overlapped com deadline e cancelamento verificados em fatias, para
que nem uma conexão que nunca chega nem um peer mudo bloqueiem o servidor. Um
timeout cancela a operação e aguarda sua conclusão antes de liberar buffers.
Leituras curtas são normais; o enquadramento das ADRs 0023 e 0024 é quem
delimita mensagens.

## Limites e fronteira de confiança

Este canal não protege contra um usuário que já pode depurar o servidor: quem
tem esse acesso lê o segredo da memória. Também não atesta que a imagem
carregada no alvo é o artefato aprovado, não implementa heartbeat, fila ou
dispatcher, e não existe fora do Windows — nas demais plataformas a fábrica
retorna `unsupported`, sem caminho alternativo.

O peer controlado é sintético: ele prova o protocolo de ponta a ponta, não a
compatibilidade com *God of War* (2018). Suporte à build real continua
dependendo da evidência da etapa 0 e de uma bridge real.

## Verificação

Canal criado com ACL e instância única; conexão local aceita; PID divergente
recusado; deadline de accept sem peer; deadline de leitura com peer mudo;
cancelamento; endpoint inexistente; fechamento durante I/O; handshake completo
e stream de reflexão sobre o pipe real, com catálogo publicado no domínio;
segredo entregue por stdin e ausente de argv e ambiente.

Referências: [ADR-0023](0023-santa-monica-reflection-stream.md),
[ADR-0024](0024-santa-monica-bridge-handshake.md),
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).
