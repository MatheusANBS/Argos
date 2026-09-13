# ADR-0027 — Reflexão nativa normalizada e confinada ao módulo

Status: aceito; continuação autorizada da implementação da Spec 0014.

## Contratos

A família `gow2018-reflection-x64-v2` ancora TypeDecl em seu início real
(`+0x00/08/10/18`), lendo a base em `+0x28` e a faixa de atributos em
`+0x20/24`. A família anterior é recusada: seus RVAs não podem ser reinterpretados
silenciosamente. O operador deve migrar família e limites juntos.

O perfil mantém os nove campos da ADR-0026 e pode acrescentar seis RVAs:
`attribute_begin|attribute_end|enum_begin|enum_end|sli_begin|sli_end`.
São aceitos exatamente nove ou quinze campos. Um par `0|0` omite a tabela;
faixas parciais, invertidas, não integrais ou fora da imagem são recusadas.
O digest canônico inclui o hash do módulo e todas as faixas.

TypeDecl e EnumDecl são indexados antes da emissão. Atributos são lidos da
tabela contígua no módulo; nunca se segue `TypeDecl::m_Members` no heap.
Só se publica o atributo cuja posição está na faixa declarada pelo seu dono,
com `+0x18 == 0xFFFF` (sem atributo externo) e bounds válidos. Isso elimina
cópias herdadas e views embutidas sem heurística sobre a grafia do nome.
O catálogo continua validando unicidade, ciclos, referências e bounds.

Nomes de enum se repetem entre declarações distintas. Sua chave é o índice
da tabela mais um, no espaço de IDs de enum e vinculado ao perfil/contexto;
não se usa hash apenas do nome. Tipos e funções preservam IDs por nome.

Ponteiros, arrays e mapas podem descrever armazenamento sem tipo referenciado
quando o metadado não identifica um tipo de domínio; objetos embutidos continuam
exigindo referência e tamanho exatos. Referência presente e inválida nunca vira
referência ausente. Mapas sem tamanho comprovado são omitidos e contados; as
tabelas auxiliares de arrays/mapas e propriedades SLI ficam para outra entrega.
SLI permanece descritivo; assinatura vazia ou ilegível é rejeitada, nunca
inferida de falha ou ponteiro nulo.

Toda leitura, inclusive arrays de nomes/valores de enum, é limitada à imagem
com aritmética por subtração. Strings ficam na janela do perfil. Erro de I/O,
cancelamento, deadline ou orçamento encerra a instância; metadados estruturalmente
inválidos são omitidos e contados. Tetos limitam tabelas, índices temporários,
bytes lidos e registros antes de alocar/trabalhar. Ownership é local à descoberta,
sem threads próprias; o RuntimeMemoryView emprestado deve sobreviver ao reader.

O resultado permanece `validated_best_effort` e `coverage_complete: false`:
não há atestação da imagem nem cobertura das tabelas auxiliares/propriedades.
Não há escrita, execução SLI, Lua, inventário ou dispatcher nesta entrega.

## Verificação

Fixtures independentes dos offsets do reader devem cobrir herança, cópias
herdadas, views embutidas, campos de tipos primitivos e de objetos, enums u64,
SLI, limites, falhas de I/O, referências inválidas, overflow, leitura fragmentada,
cancelamento e ausência de leituras externas. A integração MCP verifica o
encaminhamento do perfil e consulta dos registros. Builds dev e ASan com os
warnings do projeto são obrigatórias. Evidência no jogo é complementar e não
substitui os testes sintéticos.

Referências: [ADR-0026](0026-santa-monica-native-type-reader.md),
[evidência](../engines/gow2018-steam-11168363-evidence.md).
