# 🔐 Fluxo de Autenticação e Controle de Acesso

## Cadastro
1. Usuário envia email/senha.
2. Senha é hasheada.
3. Usuário é salvo no banco.

## Login
1. Verifica email e senha.
2. Se válido, salva dados na sessão:
   - session['user_id']
   - session['role']
   - session['email']

## Verificação de Permissão
- Se 'user_id' não estiver na sessão, redireciona.
- Verifica 'role' para acesso de admin.

## Logout
- session.clear()
- Redireciona para a página inicial.
