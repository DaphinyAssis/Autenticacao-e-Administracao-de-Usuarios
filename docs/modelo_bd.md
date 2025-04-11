#  🛢 Modelagem do Banco de Dados (Diagrama Entidade-Relacionamento)

## Tabela: User

| Campo         | Tipo         | Restrições                       |
|---------------|--------------|----------------------------------|
| id            | Integer      | PK, Auto Increment               |
| email         | Varchar(150) | UNIQUE, NOT NULL                 |
| password      | Varchar(200) | NOT NULL                         |
| role          | Varchar(50)  | DEFAULT 'user'                   |
| created_at    | DateTime     | DEFAULT datetime.utcnow          |
| is_active     | Boolean      | DEFAULT True                     |
| is_anonymized | Boolean      | DEFAULT False                    |


