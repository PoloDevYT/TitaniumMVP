# TitaniumMVP

Landing page + backend minimalista para o ecossistema Titanium PRO. O projeto expõe uma API em Express com autenticação JWT, persistência SQLite e páginas estáticas para a jornada do cliente.

## Pré-requisitos
- Node.js 18+
- npm
- SQLite (instalado no sistema)

## Configuração rápida
1. Instale dependências:
   ```bash
   npm install
   ```
2. Crie o arquivo `.env` a partir do template (o servidor carrega automaticamente, sem dependências externas):
   ```bash
   cp .env.example .env
   ```
3. Inicialize banco e dados iniciais (admin + treinos de catálogo):
   ```bash
   npm run db:setup
   ```
4. Suba o servidor HTTP:
   ```bash
   npm start
   ```

O servidor roda na porta definida em `PORT` (padrão: `3000`).

## Variáveis de ambiente
- `PORT`: porta do servidor Express.
- `JWT_SECRET` / `JWT_EXPIRES_IN`: segredos e tempo de expiração do token.
- `BCRYPT_SALT_ROUNDS`: fator de custo usado no hash de senha.
- `CORS_ORIGIN`: lista de origens permitidas (separe com vírgula). Em branco libera tudo em desenvolvimento.
- `NODE_ENV`: `development` ou `production`.
- `ALLOW_MOCK_UPGRADE`: habilita o endpoint de upgrade fictício (somente para testes).
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`, `ADMIN_PLAN`: credenciais usadas pelo `npm run db:setup` para criar/atualizar o usuário administrador.

## Estrutura de dados
O módulo `database.js` cria e sincroniza automaticamente as tabelas necessárias ao carregar o servidor:
- `users` (campos de plano e papel incluídos por padrão)
- `user_stats`
- `workouts` e `user_workouts`
- `progress_entries`
- `community_posts`
- `logs`
- `settings`

O script `scripts/setupDb.js` também popula treinos de exemplo e garante a existência de um administrador com o plano configurado.

## Endpoints úteis
- `POST /api/register` — cria usuário e devolve token
- `POST /api/login` — autenticação
- `GET /api/dashboard` — dados do usuário logado
- `GET /api/workouts` — catálogo premium (planos `iron`/`black`)
- `GET /api/admin/users` — lista usuários (acesso `admin`)

Outras rotas podem ser consultadas em `server.js`.

## Boas práticas
- Defina um `JWT_SECRET` forte em produção.
- Desative `ALLOW_MOCK_UPGRADE` fora de ambientes de teste.
- Faça backup do arquivo `titanium.db` antes de rodar novas versões do servidor.
