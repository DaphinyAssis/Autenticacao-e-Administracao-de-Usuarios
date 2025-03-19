# 🚀 Módulo de Autenticação e Gestão de Usuários 🔐

## 🎯 Objetivo
Desenvolver um módulo de autenticação e gestão de usuários que possa ser integrado a outros projetos, garantindo **segurança**, **conformidade com a LGPD** e **boas práticas de desenvolvimento**.

---

## ⚡ Funcionalidades
✅ Cadastro de usuários  
✅ Login seguro com autenticação  
✅ Controle de permissões baseado em papéis (**RBAC - Role-Based Access Control**)  
✅ Reset de senha seguro  
✅ Registro de logs de acesso e alterações  
✅ Exclusão de conta conforme **LGPD**  
✅ Anonimização ou Pseudoanonimização conforme **LGPD**  

---

## 📜 Requisitos
Os requisitos do projeto estão documentados no arquivo 📄 [requisitos.md](requisitos.md).

---

## 🛠️ Tecnologias Utilizadas
- **🖥️ Linguagem de programação:** Python 🐍
- **📦 Framework:** Django ou Flask
- **🗄️ Banco de dados:** PostgreSQL ou SQLite
- **🔒 Ferramentas de segurança:** bcrypt para hash de senhas, proteção contra ataques de força bruta

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
   cp .env.example .env
   ```
5. **Execute a aplicação:**
   ```sh
   python manage.py runserver  # Para Django
   flask run  # Para Flask
   ```

---

## 🤝 Contribuição
Este Projeto foi feito por Daphiny Assis e Guilherme Yuri