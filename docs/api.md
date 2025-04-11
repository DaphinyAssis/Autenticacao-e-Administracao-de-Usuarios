# 📡 API REST (Formato e Endpoints)

## 🔐 Autenticação
- Sessão com cookies (HTTPOnly).
- Retorno padrão:
  - { "success": "..." }
  - { "error": "..." }

## Endpoints

### POST /register
- Campos: email, password, role
- Resposta:
  { "success": "Usuário registrado com sucesso" }

### POST /login
- Campos: email, password
- Resposta:
  { "success": "Login bem-sucedido", "role": "admin" }

### GET /user_info
- Resposta:
  {
    "email": "usuario@exemplo.com",
    "role": "user"
  }

### POST /delete_account
- Resposta:
  { "success": "Conta excluída e dados anonimizados" }

### GET /api/users  (Apenas admin)
- Resposta:
  [
    {
      "id": 1,
      "email": "teste@exemplo.com",
      "role": "admin",
      "active": true
    },
    ...
  ]