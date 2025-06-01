# 📌 Requisitos do Projeto 

### (Mais detalhados em 📄 [especificacoes.md](especificacoes.md).)

## 🔹 1. Requisitos Funcionais
✅ Cadastro de usuários com e-mail e senha  
✅ Login com autenticação segura (hash de senha)  
✅ Controle de permissões com papéis: `admin` e `user` (**RBAC**)  
✅ Reset de senha com envio de token temporário  
✅ Registro de logs de eventos importantes (registro, login, reset, anonimização)  
✅ Exclusão e anonimização de conta conforme **LGPD**  
✅ Painel de administração acessível apenas por usuários com papel `admin`  
✅ API com listagem de usuários (restrita a admins)

---

## 🔹 2. Requisitos Não Funcionais
🔒 **Segurança:**  
- Senhas protegidas com `generate_password_hash()`  
- Verificação com `check_password_hash()`  
- Tokens seguros com `itsdangerous`  
- Sessões protegidas com cookies HTTP-only  

🔧 **Modularidade:**  
- Arquitetura pronta para integração com sistemas Flask maiores  

📑 **APIs documentadas:**  
- Endpoints RESTful com retorno em JSON para login, cadastro, reset e exclusão  

⚡ **Escalabilidade:**  
- Uso de SQLAlchemy permite troca de banco (SQLite ↔ PostgreSQL) sem alterar lógica  
- Estrutura permite futura adoção de JWT, OAuth2, etc.  