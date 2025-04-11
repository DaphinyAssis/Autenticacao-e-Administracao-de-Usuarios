# 🚀 Módulo de Autenticação e Gestão de Usuários 🔐

## 🎯 Objetivo
Desenvolver um módulo de autenticação e gestão de usuários com Flask, que possa ser integrado a outros projetos, garantindo **segurança**, **conformidade com a LGPD** e **boas práticas de desenvolvimento**.

---

## ⚡ Funcionalidades
✅ Cadastro de usuários  
✅ Login seguro com autenticação (hash de senha com `werkzeug.security`)  
✅ Controle de permissões baseado em papéis (**RBAC - Role-Based Access Control**)  
✅ Reset de senha com token temporário (`itsdangerous`)  
✅ Registro de logs de acesso e alterações (`access.log`)  
✅ Exclusão de conta com **anonimização** de dados conforme **LGPD**  
✅ Painel de administração com visualização de usuários ativos  
✅ API de usuários para admins autenticados

---

## 📜 Requisitos
Os requisitos do projeto estão documentados no arquivo 📄 [requisitos.md](requisitos.md).

---

## 🛠️ Tecnologias Utilizadas
- **🖥️ Linguagem de programação:** Python 🐍
- **📦 Framework:** Flask
- **🗄️ Banco de dados:** SQLite
- **🔐 Segurança:**
  - `werkzeug.security` para hashing de senhas
  - `itsdangerous` para geração e verificação de tokens
  - Proteção de sessão (`SESSION_COOKIE_HTTPONLY`)
- **📝 Logs:** Registro de eventos de login, registro e reset em `access.log`

---

## 🚀 Instalação
1. **Clone este repositório:**
   ```sh
   git clone https://github.com/seu-usuario/modulo-autenticacao.git
   ```
2. **Crie e ative um ambiente virtual:**
   ```sh
   cd modulo-autenticacao
   python -m venv venv
   source venv/bin/activate  # No Windows: venv\Scripts\activate
   ```
3. **Instale as dependências:**
   ```sh
   pip install -r requirements.txt
   ```
4. **Configure as variáveis de ambiente:**
   ```sh
   export FLASK_APP=app.py
   export FLASK_ENV=development
   ```
5.**Inicialize o banco de dados:**
```sh
python
>>> from app import db
>>> db.create_all()
>>> exit()
```
5. **Execute a aplicação:**
   ```sh
   flask run
   ```

---

## 🤝 Contribuição
Este Projeto foi feito por Daphiny Assis e Guilherme Yuri