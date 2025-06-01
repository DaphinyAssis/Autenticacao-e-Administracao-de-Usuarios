# 📋 Especificações do Sistema (Funcionais e Não Funcionais)


## ✅ Funcionais

1. Cadastro de usuários com email, senha e papel (role).
2. Login com autenticação por email e senha.
3. RBAC:
   - `admin` acessa painel e API de usuários.
   - `user` acessa somente seus dados.
4. Reset de senha por link enviado por email (token válido por 1 hora).
5. Área autenticada protegida.
6. Anonimização de conta conforme LGPD.
7. Registro de logs de login, registro e exclusão.
8. Painel administrativo com listagem de usuários.
9. API REST para listar usuários (admin).

## 🔒 Não Funcionais

- Hash seguro de senha (`werkzeug.security`).
- Tokens seguros com validade (`itsdangerous`).
- Cookies com flag HTTPOnly.
- Estrutura modular.
- Preparado para migração para PostgreSQL.
- Registro de logs em arquivo `access.log`.
- Conformidade com LGPD.