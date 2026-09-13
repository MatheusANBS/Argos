# God of War PC — evidência inicial da instalação Steam 11168363

## Estado atual — reader de reflexão v2

A [ADR-0027](../adr/0027-santa-monica-native-reflection.md) substitui o reader
inicial e corrige as hipóteses históricas preservadas abaixo. Validação pelo
executável MCP de desenvolvimento, com sessão `read_only`, no processo já
aberto do operador: **1.192 tipos, 7.041 campos próprios, 482 enums, 3.791 valores
e 309 funções SLI**. `tResourcesPerm` devolveu quatro campos representáveis;
`tDriverBank`, 66 campos incluindo herança. SLI reportou `invocable: false`.
Descoberta medida em 0,699 s, com 2.182.536 bytes retidos pelo catálogo, Windows
x64/MSVC Debug. É uma observação única, não p95/p99 nem garantia de latência.

Correções verificadas na continuação:

- TypeDecl começa em `0x11DAA70` e termina em **`0x11F20D0`**, fim exclusivo
  para 1.198 slots de 80 bytes. `0x11F2080` deixava de fora o último slot.
  Seis slots ainda são rejeitados pela validação estrutural conservadora.
- TypeAttribute tem **19.275 slots**, faixa `0x1082030..0x1118990`. Os 18.775
  registrados antes eram entradas de membros observadas, não o comprimento
  da tabela contígua. Ela contém cópias herdadas e views de objetos embutidos.
- A seleção normalizada exige posição dentro da faixa `+0x20/+0x24` do tipo
  dono e `+0x18 == 0xFFFF` no atributo. Somente agrupar por dono e conferir
  `offset < size` ainda produz duplicatas. A regra usa índices, não nomes.
- EnumDecl ocupa `0x1184E70..0x1188AB0`. Vários enums têm o mesmo nome;
  a identidade precisa do índice da declaração, não apenas do nome.
- Funções SLI ocupam **`0x11CA300..0x11CC9A0`** (309 registros). As 86
  propriedades começam imediatamente depois; percorrer 395 registros mistura
  registries com contratos de callback diferentes.
- Nomes e arrays de valores dos enums usados ficam na imagem. O array de
  membros de TypeDecl pode estar no heap e não é seguido pelo reader.

Perfil usado apenas na validação local (nada foi habilitado na configuração
persistente do cliente nesta rodada): família `gow2018-reflection-x64-v2`,
tamanho/hash da instalação abaixo, faixas acima e janela de nomes
`0xD48000..0x105A000`. Todos os fins são exclusivos.

`coverage_complete` permanece falso: tabelas auxiliares de arrays/mapas,
mapas sem tamanho comprovado e propriedades SLI ficam de fora. Nenhum campo
é promovido a acesso de instância, nenhuma função é invocada, e o digest do
arquivo continua sendo uma afirmação do perfil, sem atestação da imagem viva.

## Histórico de investigação

As seções anteriores à procedência de terceiros registram hipóteses e
resultados de etapas antigas. As afirmações de ausência de campos/herança
e os números anteriores foram superados pelo estado atual acima.

Coleta: 2026-09-12, instalação indicada pelo operador. Inspeção somente leitura
de manifesto Steam, version resource, hash e cabeçalho PE; jogo não iniciado
nem instrumentado durante esta coleta. Nenhum byte proprietário é distribuído.

| Dado observado | Valor |
|---|---|
| Steam App ID | `1593500` |
| Steam build ID no manifesto local | `11168363` |
| Executável | `GoW.exe` |
| Comprimento do arquivo | `20083552` bytes |
| ProductVersion | `GoW-4757534-Wed May 25 11:52:20 2022` |
| FileVersion | `0,0,0,0` |
| SHA-256 do arquivo | `caebcb027980d7eac9203d190f9ee649eebc549f8defce138e2114dc91f40452` |
| PE Machine / optional-header magic | `0x8664` (x64) / `0x020B` (PE32+) |
| PE SizeOfImage | `85839872` bytes |
| Seções / COFF timestamp bruto | `8` / `1653506097` |

O build ID vem de um manifesto local, não de atestação da distribuição. A
versão textual e o timestamp não substituem SHA-256. Estes dados identificam
o arquivo observado; não provam que esteja íntegro perante o distribuidor nem
que sua imagem carregada corresponda ao arquivo. Não há processo, época de
bridge ou imagem carregada validados nesta coleta.

## Coleta em runtime — sessão somente leitura (2026-09-12)

Método: `memory_debug_attach` com `authorized: true` no processo do operador
(`GoW.exe`, mesmo usuário), acesso `read_only`. O caminho usa
`OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory`, **não** a API de depuração
do Windows: nenhum debugger foi anexado, nenhuma escrita, nenhuma injeção e
nenhuma tentativa de contornar proteção. As leituras funcionaram sem bloqueio
do anti-tamper. Endereços absolutos desta sessão não são reproduzíveis (ASLR);
tudo abaixo é registrado como RVA sobre `GoW.exe`.

### Mapa de imagem observado

| Região | RVA | Tamanho | Atributos |
|---|---|---:|---|
| Cabeçalho | `0x0` | 4.096 | r |
| Código | `0x1000` | 13.922.304 | r-x |
| Dados somente leitura | `0xD48000` | 3.219.456 | r |
| Dados graváveis | a partir de `0x105A000` | ~65 MiB | rw |

`SizeOfImage` observado em runtime bate com o do arquivo (85.839.872). O
espaço de endereçamento total do processo tinha ~10,2 GiB legíveis em 14.773
regiões no momento da coleta.

### RTTI do MSVC presente e legível

A imagem **conserva os descritores de tipo do MSVC**. Varredura por `.?AV`
(classe) sobre os 85.839.872 bytes do módulo encontrou um bloco contíguo de
descritores:

| Dado observado | Valor |
|---|---|
| Início do bloco | RVA `0x11F3EF0` |
| Limite superior | RVA `0x1230000` (nenhum descritor acima disso) |
| Extensão | ~245 KiB |
| Ocorrências isoladas antes do bloco | RVA `0x105A010`, `0x105A040` |

Enumeração completa posterior **corrigiu a estimativa inicial** (que supunha 5
a 6 mil classes a partir do tamanho do bloco). Os números reais, obtidos
percorrendo a imagem inteira e validando cada *complete object locator* pelo
campo `pSelf`:

| Dado observado | Valor |
|---|---|
| Descritores de tipo | 1.662 |
| *Complete object locators* válidos | 1.745 |
| Classes com hierarquia reconstruída | 1.633 |
| Classes com vtable localizada | 1.633 |
| Classes com herança múltipla | 211 |
| Classes com herança virtual | 0 |
| Classes com mais de uma vtable | 88 |

A hierarquia vem do *class hierarchy descriptor* e do *base class array*, e a
vtable de cada classe foi localizada pelo ponteiro para o seu locator. As
cadeias mais profundas têm 13 bases (por exemplo `sm::Boat` ⟵ `sm::Vehicle`
⟵ `physics::CustomClient` ⟵ `dc::Client<tPhysicsCustomClient>` ⟵
`dc::ClientBase`).

Nomes **observados** por amostragem, agrupados por prefixo — são os nomes reais
da build, lidos da instalação do operador:

| Prefixo/namespace | Exemplos observados |
|---|---|
| `sm` (namespace) | `AllocatorInterface@sm`, `Pass@sm`, `PassParticlesSync@sm`, `WindServer@sm` |
| `sys` | `sysFile`, `sysFileBase`, `sysFileMem` |
| `svr` (framework servidor/contexto) | `svrServerBase`, `svrContextBase`, `svrClient`, `svrClientList`, `svrMultiContext`, `svrContext<svrListContainer>`, `svrArrayListContainer<N>` |
| `ren` (render) | `renModelServer`, `renTextureServer`, `renLightServer`, `renMaterialServer`, `renStreamedLod`, `renStreamedObj`, `renStreamedTex`, `renPSDPass` |
| `anm` (animação) | `anmNode`, `anmRootNode`, `anmPlayList`, `anmBalanceBlendNode`, `anmCombatBlendNode`, `anmWalkBlendNode`, `anmClimbBlendNode`, `anmStrafeBlendNode`, `anmUVBlendNode`, `anmMultiSample`, `anmFlipbookIndex` |
| `go` (game object) | `goClient`, `goClientListNode`, `goAttachmentClient` |
| `dc` (namespace) | `ClientBase@dc`, `Client<tPreStream>@dc`, `Client<tSmLight>@dc`, `Client<tGIVolume>@dc`, `Client<tMirrorShadowRegion>@dc`, `Client<tVolumetricFogDensityMap>@dc` |
| `wyp` (navegação) | `wypClient`, `wypGraphClient`, `WypAllocator`, `WypMeshProcess` |
| Lua | `LuaServer`, `LuaContext` |
| `Pass*` (render passes) | `PassFade`, `PassCopy`, `PassVideo`, `PassCullBoundingBoxes`, `PassCombinedPostEffects`, `PassShadowShowSplits`, `PassWaitForReflection`, `PassClearBackground`, `PassPsdSync` |
| Middleware | Wwise (`CAkVPL*`, `CAkThreadedBankMgr`, `AK::IAk*`), Recast/Detour (`rcContext`, `dtTileCache*`), Steam (`CCallback`, `npTrophies::CSteamAchievements`) |

Isso confirma, a partir da própria build, o que a investigação preliminar
apenas sugeria: existe hierarquia polimórfica rica, com arquitetura
servidor/cliente/contexto por subsistema, e **o runtime Lua está presente**.

### Tabela de tipos do próprio engine

Além do RTTI do compilador, a build tem um **registro de tipos próprio**. Ele
foi localizado partindo de um nome que aparecia fora do bloco RTTI
(`GivePlayerPickupFeature`, `IncrementXP`), seguindo o ponteiro que o
referencia.

Em `.rdata`, por volta de RVA `0xEB1000`, há pares de strings `t<Nome>` e
`<Nome>` — `tRecipe`/`Recipe`, `tRecipeItem`/`RecipeItem`,
`tResourceStatus`/`ResourceStatus`, `tWeapon`, `tShield`, `tDefaultStats`,
`tAttachments`, `tVehicle`, `tRagdollParameters`, `tLuaDecision`, `tDTree`…
Esses `t*` são os mesmos tipos que aparecem como parâmetro de
`dc::Client<t…>` no RTTI do compilador.

Em `.data` há a tabela de descritores que os referencia, com passo de 80 bytes:

| Dado observado | Valor |
|---|---|
| Extensão da tabela | RVA `0x11DAA70` .. `0x11F2080` (1.198 registros) |
| Passo entre registros | 80 bytes |
| Tipos enumerados | 1.198 |
| Registros com tamanho zero | 0 |

Layout do registro — **corrigido em 2026-09-12**. A leitura anterior partia de
RVA `0x11DAA40`, que fica 48 bytes (`0x30`) antes do primeiro registro real. O
deslocamento se compensava: `+0x30` da origem errada cai exatamente sobre o
`+0x00` do registro seguinte, de modo que nome, tamanho e alinhamento saíam
corretos por acidente, enquanto os campos de herança e de membros ficavam
invisíveis. O início real é RVA `0x11DAA70`:

| Offset | Conteúdo |
|---:|---|
| `+0x00` | ponteiro para a string `t<Nome>` |
| `+0x08` | ponteiro para a string `<Nome>` |
| `+0x10` | **tamanho do tipo, em bytes** |
| `+0x18` | **alinhamento** e flags |
| `+0x20` | índice do primeiro atributo do tipo |
| `+0x24` | quantidade de membros |
| `+0x28` | índice do tipo herdado (`0xFFFF` = nenhum) |
| `+0x30`, `+0x38` | ponteiros para o hash do nome; nulos na maioria |
| `+0x40` | ponteiro para o array de membros (entradas de 16 bytes) |

Exemplos observados: `tRecipeItem` 32 B/8, `tRecipe` 64 B/8,
`tResourceStatus` 16 B/8, `tResourcesPerm` 120 B/8, `tWeapon` 80 B/8,
`tShield` 192 B/8, `tCombat` 240 B/8, `tEntity` 40 B/8, `tCamera` 504 B/8,
`tSmLight` 192 B/16.

O ponteiro de `+0x20` leva a uma tabela no heap com entradas de 16 bytes no
formato {valor de 64 bits com aparência de hash, id sequencial}. O id do tipo
aparece nessa tabela junto de ids vizinhos, o que sugere um mapa
hash → id compartilhado entre tipos e seus membros. Os 90 registros com
`+0x10`/`+0x18` preenchidos são os tipos de base mais fundamentais
(`tColorMod`, `tVector3F`, `tVector4`, `tJointRef`, `tInputPlug`, `tAnimNode`);
apontam para estruturas esparsas com nomes curtos embutidos, compatíveis com
tabelas hash.

### Sistemas de gameplay identificados pelo RTTI

O grafo de classes expõe, por nome, os subsistemas que a Spec 0014 pretendia
alcançar:

- **Itens/pickup**: 58 classes em `pickup::` — `Base`, `Weapon`,
  `GivePlayerPickupFeature`, `GiveOthersPickupFeature`, `ModifyAttributesFeature`,
  `TryAutoUpgradeOnApplyFeature`, `EmitOrbsFeature`, `AttractOrbsFeature`…
  É um sistema de composição por *features*, não um array de inventário.
- **Recursos/economia**: `resources::IncrementXP`, `IncrementPlayerCounter`,
  `AddResourceAtThreshold`, `ModifyAttribute`, `NotifyPickup`,
  `RelinquishPickup`, com eventos `ResourceAmountChangeMessage` e
  `RuneAddedMessage`.
- **Comandos tipados**: 313 classes `*Request` e um template
  `RequestWithType<>` — `AddBuffRequest`, `CreateTokenRequest`,
  `DeleteTokenRequest`, `IncrementPlayerCounterRequest`, `EmitArrowRequest`,
  `BreakBreakableRequest`… É o análogo mais próximo do que o plano chamava de
  "invocação SLI", e já existe no engine.
- **Lua**: 90 classes, incluindo `LuaServer`, `LuaContext`, `LuaClient`,
  `LuaTableClient`, `ExecuteLua*CallbackRequest` e, principalmente,
  `ScopedLuaRequestQueue` / `…Immediate` / `…Deferred` — ou seja, o caminho
  Lua→nativo passa por uma fila de requests tipados.
- **Save**: `Binary_SaveListItem`, `Entity_SaveListItem`, `Enemy_SaveListItem`,
  `GOState_SaveListItem`, `Object_SaveListItem`.

### Confirmação pelo reader do servidor

O reader nativo da [ADR-0026](../adr/0026-santa-monica-native-type-reader.md)
percorre a mesma tabela pela sessão de depuração autorizada e publica, nesta
build, **1.192 tipos** com nome, tamanho e id estável — dez a mais que a
colheita exploratória, porque aquela heurística exigia prefixo `t` seguido de
maiúscula e deixava de fora nomes legítimos como `SlashWound`,
`WeaponEmbedPoints`, `EmbedPoint`, `BinaryDecalSet` e `ConfigSpec`. Os 1.192
nomes e os 1.192 ids são únicos, sem colisão, e os tamanhos vão de 1 a 2.856
bytes. Nenhum campo, enum ou entrada SLI é publicado, porque não há nenhum na
tabela: `coverage_complete` é sempre falso.

### Sondagens que fecharam caminhos

Tentativas de chegar ao metadado de campo por padrão em memória, todas
registradas para não serem repetidas:

- **Array ascendente de ids** (RVA `0x2E32988`..`0x2E40734`, 14.187 entradas de
  `0x895` a `0x3FFF`, com sentinelas `0xFFFFFFFE`/`0xFFFFFFFF`): é um *pool de
  ids livres*, não uma tabela de descritores.
- **Tabela de 16 bytes** `{chave u32, par u32, ponteiro}` perto de RVA
  `0x133C0A8`: é um registro de **materiais**. Seguindo o ponteiro e lendo o
  `+0x00` como vtable, as entradas resolvem para `renMaterial` pelo grafo RTTI
  colhido. Útil como prova de que nomear objeto do heap por vtable funciona,
  mas não tem relação com tipos de dado.
- O valor em `+0x00` do registro de tipo **não é um id utilizável**: há
  duplicatas, um zero, e o `0x3385` de `tRecipeItem` colidiu com um id de
  material, o que gerou uma pista falsa.
- Classes polimórficas para recursos **não existem**: busca por `wallet`,
  `inventory`, `perm`, `recipe` e `currency` no grafo RTTI retorna zero. O
  armazenamento é POD, então não há vtable para localizar instâncias.

### Mapa de persistência do jogador

O próprio catálogo de tipos, porém, expõe a forma do estado persistente:

| Tipo | Tamanho | Alinhamento |
|---|---:|---:|
| `tResourcesPerm` | 120 | 8 |
| `tRecipesPerm` | 32 | 8 |
| `tWalletsPerm` / `tWallet` | 16 | 8 |
| `tComponentsPerm` | 16 | 8 |
| `tResource` (definição) | 64 | 8 |
| `tResourceStatus` | 16 | 8 |

O sufixo `Perm` marca estado persistente do jogador. `tResourcesPerm` com 120
bytes comporta 30 contadores de 32 bits, compatível com a quantidade de
recursos do jogo. Isso **não** identifica qual slot é qual recurso — para isso
ainda é preciso um experimento com valor conhecido —, mas delimita o bloco e
substitui a varredura cega por uma leitura estruturada de 120 bytes.

### O que continua faltando

Os nomes e offsets de **campo** não foram localizados. O registro de tipos dá
nome, tamanho e alinhamento — não a lista de membros. As tabelas de hash
encontradas sustentam a hipótese de que membros sejam endereçados por hash de
64 bits, não por string; se for isso, recuperar nomes de campo exigiria um
dicionário de candidatos e verificação por hash, não simples leitura.

Localizar o layout de campos a partir daqui exige desmontar o código que
popula esses registros — trabalho de engenharia reversa sustentado, não mais
reconhecimento de padrões em memória. Enquanto isso não existir, as tools
`santamonica_runtime_type`, `_enums` e `_sli_functions` **não têm com o que ser
alimentadas nesta build**, e responder `unsupported` continua sendo a resposta
honesta.

### Artefatos desta coleta

Ficam fora do repositório, por serem metadados derivados de binário
proprietário: o grafo de classes RTTI (1.633 entradas, com bases e vtables) e
a tabela de tipos do engine (1.182 entradas, com tamanho e alinhamento). Ambos
são reproduzíveis pelo operador na própria instalação; nenhum byte do jogo é
distribuído aqui.

### Correção de uma conclusão intermediária

Uma sondagem anterior desta mesma coleta concluiu que "não há registro de nomes
paralelo ao do compilador", porque a string `anmBalanceBlendNode` aparecia uma
única vez na imagem, dentro do descritor MSVC. Essa conclusão estava **errada**,
e o erro foi de amostragem: `anmBalanceBlendNode` é uma classe C++, não um tipo
de dado do engine. Testando nomes de outra natureza (`GivePlayerPickupFeature`,
`IncrementXP`) apareceram ocorrências fora do bloco RTTI, e foram elas que
levaram à tabela `t*` descrita acima. A string `RTTI` continua ausente do
módulo — isso permanece verdadeiro e apenas significa que o sistema não se
identifica por esse nome.

### Consequência para a Spec 0014

A etapa 0 avançou de forma concreta, mas **não está satisfeita**. O que existe
hoje sustenta um perfil de *tipos e hierarquia* por build, derivado do RTTI do
compilador. Não sustenta ainda reflexão de campos/enums/SLI, que é o contrato
das tools de reflexão. Habilitar suporte à build sem isso seria anunciar
capacidade que não existe.

Concluídos nesta coleta: enumerar o bloco de descritores e reconstruir a
hierarquia pelos *complete object locators*; correlacionar as vtables; e
localizar e enumerar a tabela de tipos do próprio engine, com tamanho e
alinhamento.

Próximos passos concretos, em ordem de valor:

1. Desmontar a rotina que popula os registros `t*` para descobrir onde ficam os
   membros — é o único caminho que ainda pode render offsets de campo.
2. Se os membros forem endereçados por hash, identificar a função de hash e
   testar um dicionário de nomes candidatos contra os ids observados.
3. Correlacionar `dc::Client<t…>` (RTTI) com o registro `t*` para ligar a
   classe C++ ao tipo de dado, o que já permite nomear instâncias por vtable.
4. Aceitar `unsupported` como resultado legítimo caso (1) e (2) não produzam
   layout verificável: um perfil de tipos e tamanhos **não** é reflexão de
   campos, e não deve ser apresentado como tal.

Antes de criar um perfil executável, ainda é necessário:

1. Determinar os módulos relevantes e a verificação da imagem carregada com
   ASLR/relocations e alterações esperadas de hooks.
2. Obter, por investigação independente autorizada, os layouts/raízes RTTI e
   SLI e registrar evidência estrutural, limites e escopo de cobertura.
3. Validar a bridge Argos, identidade de peers e dispatcher em alvo controlado.
4. Comprovar reflexão somente leitura nesta build antes de habilitar qualquer
   capacidade; inventário, transações e Lua têm critérios adicionais.

Não se registra assinatura/RVA fictícia, perfil em allowlist nem promessa de
compatibilidade com outra instalação de mesmo build ID. Consulte a
[Spec 0014](../specs/0014-santa-monica-kinetica-runtime-instrumentation.md).

## Procedência: fatos de terceiros (2026-09-12)

Até esta data tudo neste documento vinha de derivação independente sobre a
instalação do autor. A partir daqui isso deixa de ser verdade e o registro
precisa dizer qual é a origem de cada fato.

O autor do repositório autorizou explicitamente a consulta a um projeto de
pesquisa de terceiros sobre este mesmo jogo. Esse projeto **não declara
licença** (o README diz textualmente que nenhuma licença foi fornecida).
Portanto:

- **Usado:** os fatos sobre o binário — assinaturas de bytes, offsets e a
  semântica dos registros de reflexão. Fatos sobre um programa não são
  expressão protegida por direito autoral.
- **Não usado:** o código daquele projeto. Nada foi copiado para o Argos; toda
  a implementação aqui é escrita do zero.

Quem auditar este documento deve tratar as assinaturas abaixo como
**verificadas nesta build** (cada uma casou com um único ponto da imagem), mas
**não** como derivação independente.

## Raízes de reflexão resolvidas por assinatura

Todas resolvidas na build 11168363, base observada `0x7FF7691D0000`, cada
assinatura com exatamente **uma** ocorrência na imagem:

| Raiz | RVA |
|---|---|
| `RTTI::TypeDeclTable` | `0x011DAA70` |
| `RTTI::TypeAttributeTable` | `0x01082030` |
| `RTTI::EnumDeclTable` | `0x01184E70` |
| `RTTI::ArrayAttributeTable` | `0x01134B60` |
| `RTTI::HashMapAttributeTable` | `0x0113A250` |
| `GameModule::SLIFunctionTable` | `0x011CA300` |
| `GameModule::SLIPropertyTable` | `0x011CC9A0` |
| `gLocalPlayerGO` | `0x022E7D50` |
| `gCameraBlender` | `0x022A93D0` |

Volumes enumerados a partir dessas raízes:

| Dado | Valor |
|---|---|
| `TypeDecl` | 1.198 |
| `EnumDecl` | 482 |
| Entradas de membro | 18.775 |
| Funções SLI | 395 |
| Propriedades SLI | 86 |

Isto **falsifica** a afirmação anterior de que a tabela não carregava herança
nem campos. Carrega as duas coisas: `+0x28` é o índice do tipo herdado e
`+0x40` aponta para o array de membros, cujas entradas indexam o
`TypeAttributeTable`. Cada atributo traz nome, offset, tamanho, tipo, e o
índice do enum quando aplicável.

Registros auxiliares, todos confirmados nesta build:

- `TypeAttribute`: 32 bytes — `+0x00` nome, `+0x08` nome do tipo, `+0x10`
  offset, `+0x12` tamanho, `+0x14` flags (2 bits baixos = flag, resto = tipo),
  `+0x16` índice do tipo dono, `+0x1A` índice auxiliar, `+0x1C` índice de enum.
- `EnumDecl`: 32 bytes — `+0x00` nome, `+0x0C` quantidade, `+0x10` array de
  nomes, `+0x18` array de valores.
- `SLIFunctionHandler` e `SLIPropertyHandler`: 32 bytes — `+0x00` nome,
  `+0x08` callback, `+0x10` string de tipos dos argumentos.

## Inventário e recursos

O tipo de dado `tResourcesPerm` (120 B, índice 725) é a **definição**, não o
saldo do jogador:

| Offset | Campo |
|---:|---|
| `+0x00` | `Array<Resource> Resources` |
| `+0x10` | `HashMap<StringHash, int32_t> ResourceIds` |
| `+0x20` | `Array<StringHash> FlagIds` |
| `+0x30` | `Array<ResourceTelemetry> Telemetry` |
| `+0x40` | `NGPResourceReplacement ReplacementOptions` |

`Array<T>` é `{T* data; uint32_t size}`, com pack de 4 — 12 bytes.

`Resource` tem 64 bytes: `+0x00` `NameId` (string), `+0x08` `LamsName`,
`+0x0C` `LamsDescription`, `+0x20` `IconName`, `+0x28` `Max`, `+0x3C`
`DisplayUi`.

Observado na instância viva: `ResourcesPerm` em `0x7FF377AE6690`, com
`Resources.data = 0x7FF377AE6708` e `size = 1676`.

O **saldo** fica em registros paralelos às definições, com o mesmo passo de 64
bytes. A primeira descrição desta seção ancorava cada entrada 0x28 bytes depois
do início real do registro; a versão confirmada pelo código do jogo está em
"Raiz do inventário e escrita de saldo", abaixo. Esse array **não** corresponde
a nenhum tipo refletido: a semântica vem de correlação e disassembly, não de
reflexão. A coerência foi conferida contra o save do autor (Elmo de Gunnr 1/1,
Marca dos Anões 4/4, Poeira Encantada 30), e os valores mudaram durante o jogo
entre leituras, o que confirma ser a carteira viva. Os outros cinco arrays com o
mesmo formato são os demais conjuntos de carteira.

Os textos exibidos ficam num blob UTF-8 separado (região de ~4 MiB, 24.651
entradas), no formato `*<id>*\n<texto>`, e o `LamsName` liga
`CommonMuspelheimLoot01` a "Brasa Ardente". Esse blob foi localizado por
varredura de texto; há globais do módulo apontando para a sua alocação, mas
nenhum índice id→texto comprovado. Por isso o produto expõe `lams_name_id` e
não resolve o texto.

Os endereços absolutos desta seção são da sessão observada. Entre execuções o
produto usa apenas RVAs de raízes endereçadas por código, descritas abaixo.

## Raiz do inventário e escrita de saldo (2026-09-13)

Globais em `.data` endereçadas por instruções do `.text` (varredura estática de
4.063.805 instruções; 36.619 globais graváveis referenciadas):

| RVA | Conteúdo |
|---|---|
| `0x502A4B0` | ponteiro para o array de conjuntos de carteira, usado pelas funções em `0x6679BF`, `0x6D7370`, `0x6D73F0`, `0x6D7598` e outras |
| `0x507B450` | o mesmo ponteiro, por outra referência de código |
| `0x2D439D4` | `u32` com o número de conjuntos (6); o código exige `> 0` antes de usar o primeiro |

O slot `RVA 0x14261C0`, que também apontava para o store, **não** é referenciado
por nenhuma instrução: é arena de dados dentro da imagem e não é usado.

Conjunto de carteira (0x50 bytes; o primeiro é o ativo): `+0x10` store e `+0x20`
contagem (1.676). O código acessa registros como `[conjunto+0x10] + idx<<6`, o
que fixa o início do registro no cabeçalho do store:

| Offset | Conteúdo |
|---:|---|
| `+0x00..0x1F` | bitset de flags (testado por `0x6D73F0` → `0x8BDEC0`) |
| `+0x20` | ponteiro opcional (componentes, em alguns registros) |
| `+0x28` | `&Resources[idx]` |
| `+0x30` | quantidade `int32` |
| `+0x34` | ordem de aquisição (`-1` se nunca adquirido) |
| `+0x38` | estado: `3` adquirido, `2` nunca adquirido |

Invariantes medidos nas 1.676 entradas: ligação `def == &Resources[i]` sem
divergência; estado `3` com quantidade ≥ 0 (444) e estado `2` com `-1` (1.230);
`ResourcesPerm` em `Resources.data - 0x78`, com `{data, size}` iguais ao store;
nomes técnicos únicos, dois deles UTF-8 não ASCII
(`Bestiary_Unlock_Svartáljǫfurr` e `Bestiary_Unlock_Hræzlyr`); 97 recursos sem
teto (`Max = -1`) e 1.577 com teto, nenhum saldo acima do teto.

Validação pelo executável MCP de desenvolvimento no processo aberto do operador,
com perfil de dezesseis campos (raiz `502A4B0`):

- `discover` em 0,78 s, com `resources_published: true`;
- `santamonica_runtime_resources` leu as 1.676 entradas em 0,67 s; as
  quantidades de `CommonMuspelheimLoot01` (9.933), `RareMuspelheimLoot01` (963),
  `RareMuspelheimLoot02` (999) e `RareMuspelheimLoot03` (0) coincidiram com a
  leitura direta da memória;
- em sessão `read_write`, `set_resource` gravou em `RareMuspelheimLoot02` o
  **mesmo** valor já presente (999 → 999), com `verified: true`, sem alterar o
  jogo;
- recusas reais: sessão `read_only` (`session_read_only`), recurso nunca
  adquirido `kPickupRageMode` (`resource_not_acquired`), `Axe` acima do teto 1
  (`exceeds_resource_max`), frase ausente (`unauthorized`) e nome inexistente
  (`resource_not_found`).

Função de concessão nativa: **não identificada**. As duas funções curtas que
usam a raiz são um comparador de 4 qwords do registro (`0x6D7370`) e um teste de
flags (`0x6D73F0`). A concessão provavelmente passa pelos componentes
`resources::components::IncrementXP`, `IncrementPlayerCounter`,
`ModifyAttribute` e `RelinquishPickup` (nomes via RTTI), cujas instâncias
referenciam o gerenciador; chamá-los exige execução na thread do jogo, que não
foi feita.
