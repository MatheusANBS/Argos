# Security policy

## Uso autorizado

Este projeto destina-se a depuração local de processos próprios ou explicitamente autorizados. Não use para acessar sistemas, processos ou dados sem permissão.

## Defaults seguros

- attach exige confirmação explícita;
- somente mesmo usuário por padrão;
- escrita desabilitada por padrão;
- limites rígidos de leitura, escrita, scan e resultados;
- nenhum recurso de injeção, stealth, bypass ou elevação;
- logs não incluem conteúdo de memória.

## Reporte de vulnerabilidade

Não abra publicamente um relatório contendo exploit funcional, dump de memória ou segredo. Forneça descrição, plataforma, versão, impacto, passos mínimos de reprodução e correção sugerida por canal privado do mantenedor do repositório onde este código for hospedado.

## Itens fora de escopo

- falhas de permissão impostas pelo sistema operacional;
- impossibilidade de anexar processos protegidos;
- bloqueios por sandbox, EDR, anticheat ou política corporativa;
- corrupção causada após o operador habilitar escrita e confirmar a chamada.
