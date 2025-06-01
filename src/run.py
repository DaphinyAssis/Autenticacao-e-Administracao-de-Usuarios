from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from zoneinfo import ZoneInfo
from datetime import datetime
import logging
import os
from functools import wraps
import time
import re
import hashlib
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import logging
import pytz

# Configurações de segurança
RATE_LIMIT_ATTEMPTS = 10
RATE_LIMIT_WINDOW = 300  # 5 minutos
BRUTE_FORCE_ATTEMPTS = 10
BRUTE_FORCE_WINDOW = 900  # 15 minutos
ACCOUNT_LOCKOUT_ATTEMPTS = 10
ACCOUNT_LOCKOUT_WINDOW = 1800  # 30 minutos

# Armazenamento em memória
rate_limit_storage = defaultdict(list)
brute_force_storage = defaultdict(list)
account_lockout_storage = defaultdict(list)
failed_login_attempts = defaultdict(int)

class SecurityDecorator:
    
    @staticmethod
    def rate_limit(max_requests=RATE_LIMIT_ATTEMPTS, window=RATE_LIMIT_WINDOW):
        """
        Proteção contra Rate Limiting - Limita número de requests por IP
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                              request.environ.get('HTTP_X_REAL_IP', 
                                                                request.remote_addr))
                if ',' in client_ip:
                    client_ip = client_ip.split(',')[0].strip()
                    
                current_time = time.time()
                
                # Limpar tentativas antigas
                rate_limit_storage[client_ip] = [
                    timestamp for timestamp in rate_limit_storage[client_ip]
                    if current_time - timestamp < window
                ]
                
                # Verificar limite
                if len(rate_limit_storage[client_ip]) >= max_requests:
                    retry_after = window - (current_time - min(rate_limit_storage[client_ip]))
                    logging.warning(f'Rate limit excedido para IP: {client_ip} - Rota: {request.endpoint}')
                    return jsonify({
                        "error": f"Muitas tentativas. Tente novamente em {int(retry_after/60)} minutos.",
                        "retry_after": int(retry_after)
                    }), 429
                
                # Registrar tentativa atual
                rate_limit_storage[client_ip].append(current_time)
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    @staticmethod
    def brute_force_protection(max_attempts=BRUTE_FORCE_ATTEMPTS, window=BRUTE_FORCE_WINDOW):
        """
        Proteção contra Brute Force - Bloqueia tentativas por email+IP
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if request.method == 'POST':
                    email = request.form.get('email', '').lower().strip()
                    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                                  request.environ.get('HTTP_X_REAL_IP', 
                                                                    request.remote_addr))
                    if ',' in client_ip:
                        client_ip = client_ip.split(',')[0].strip()
                    
                    # Chaves para rastreamento
                    email_key = f"email:{email}"
                    ip_key = f"ip:{client_ip}"
                    combined_key = f"combo:{email}:{client_ip}"
                    
                    current_time = time.time()
                    
                    # Limpar tentativas antigas para todas as chaves
                    for key in [email_key, ip_key, combined_key]:
                        brute_force_storage[key] = [
                            timestamp for timestamp in brute_force_storage[key]
                            if current_time - timestamp < window
                        ]
                    
                    # Verificar bloqueios
                    blocked_reasons = []
                    if len(brute_force_storage[email_key]) >= max_attempts:
                        blocked_reasons.append(f"email {email}")
                    if len(brute_force_storage[ip_key]) >= max_attempts * 2:  # IP pode ter mais tentativas
                        blocked_reasons.append(f"IP {client_ip}")
                    if len(brute_force_storage[combined_key]) >= max_attempts:
                        blocked_reasons.append("combinação email/IP")
                    
                    if blocked_reasons:
                        remaining_time = window - (current_time - min(
                            min(brute_force_storage[email_key], default=[current_time]),
                            min(brute_force_storage[ip_key], default=[current_time]),
                            min(brute_force_storage[combined_key], default=[current_time])
                        ))
                        
                        logging.critical(f'Brute force bloqueado - {", ".join(blocked_reasons)} - Rota: {request.endpoint}')
                        return jsonify({
                            "error": f"Conta temporariamente bloqueada por segurança. Tente novamente em {int(remaining_time/60)} minutos.",
                            "locked_until": int(current_time + remaining_time)
                        }), 423  # HTTP 423 Locked
                
                # Executar função original
                response = f(*args, **kwargs)
                
                # Se login falhou (status 401), registrar tentativa falhosa
                if (request.method == 'POST' and 
                    hasattr(response, 'status_code') and 
                    response.status_code == 401):
                    
                    email = request.form.get('email', '').lower().strip()
                    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                                  request.environ.get('HTTP_X_REAL_IP', 
                                                                    request.remote_addr))
                    if ',' in client_ip:
                        client_ip = client_ip.split(',')[0].strip()
                        
                    current_time = time.time()
                    
                    # Registrar tentativa falhosa
                    brute_force_storage[f"email:{email}"].append(current_time)
                    brute_force_storage[f"ip:{client_ip}"].append(current_time)
                    brute_force_storage[f"combo:{email}:{client_ip}"].append(current_time)
                    
                    logging.warning(f'Tentativa de login falhosa registrada - Email: {email}, IP: {client_ip}')
                
                return response
            return decorated_function
        return decorator
    
    @staticmethod
    def input_validation():
        """
        Validação básica de entrada para prevenir ataques de injeção
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if request.method == 'POST':
                    # Verificar tamanho da requisição (1MB max)
                    if request.content_length and request.content_length > 1024 * 1024:
                        logging.warning(f'Requisição muito grande: {request.content_length} bytes')
                        return jsonify({"error": "Requisição muito grande"}), 413
                    
                    email = request.form.get('email', '')
                    password = request.form.get('password', '')
                    
                    # Validação de email
                    if email:
                        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                        if not re.match(email_pattern, email):
                            logging.warning(f'Email inválido: {email} - IP: {request.remote_addr}')
                            return jsonify({"error": "Formato de email inválido"}), 400
                        
                        # Verificar se email não é muito longo
                        if len(email) > 254:
                            return jsonify({"error": "Email muito longo"}), 400
                    
                    # Validação de senha (apenas para registro)
                    if password and request.endpoint == 'register':
                        if len(password) < 8:
                            return jsonify({"error": "Senha deve ter pelo menos 8 caracteres"}), 400
                        if len(password) > 128:
                            return jsonify({"error": "Senha muito longa"}), 400
                    
                    # Verificar padrões maliciosos básicos
                    dangerous_patterns = [
                        r'<script[^>]*>.*?</script>',  # XSS básico
                        r'javascript:', r'vbscript:', r'data:',
                        r'union\s+select', r'drop\s+table', r'delete\s+from',
                        r'insert\s+into', r'update\s+.*set', r'exec\s*\(',
                        r'\.\./', r'etc/passwd', r'cmd\.exe'
                    ]
                    
                    for field_name, field_value in request.form.items():
                        if field_value and isinstance(field_value, str):
                            for pattern in dangerous_patterns:
                                if re.search(pattern, field_value, re.IGNORECASE):
                                    logging.critical(f'Possível ataque detectado - Campo: {field_name}, IP: {request.remote_addr}')
                                    return jsonify({"error": "Entrada inválida detectada"}), 400
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    @staticmethod
    def security_headers():
        """
        Adiciona headers de segurança nas respostas
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                
                # Adicionar headers de segurança se a resposta suportar
                if hasattr(response, 'headers'):
                    response.headers['X-Content-Type-Options'] = 'nosniff'
                    response.headers['X-Frame-Options'] = 'DENY'
                    response.headers['X-XSS-Protection'] = '1; mode=block'
                    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
                    
                    # Para rotas de autenticação, evitar cache
                    if request.endpoint in ['login', 'register']:
                        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                        response.headers['Pragma'] = 'no-cache'
                
                return response
            return decorated_function
        return decorator
    
    @staticmethod
    def enhanced_logging():
        """
        Log detalhado de eventos de segurança
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                start_time = time.time()
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                              request.environ.get('HTTP_X_REAL_IP', 
                                                                request.remote_addr))
                if ',' in client_ip:
                    client_ip = client_ip.split(',')[0].strip()
                    
                user_agent = request.headers.get('User-Agent', 'Unknown')[:200]  # Limitar tamanho
                
                # Log da requisição
                if request.method == 'POST':
                    email = request.form.get('email', 'N/A')
                    logging.info(f'Tentativa {request.endpoint}: {email} - IP: {client_ip}')
                
                try:
                    response = f(*args, **kwargs)
                    
                    # Log da resposta
                    duration = time.time() - start_time
                    status_code = getattr(response, 'status_code', 200)
                    
                    if request.method == 'POST':
                        email = request.form.get('email', 'N/A')
                        
                        # Log eventos importantes
                        if status_code == 200 and request.endpoint == 'login':
                            logging.info(f'LOGIN SUCESSO: {email} - IP: {client_ip} - Duração: {duration:.3f}s')
                        elif status_code == 200 and request.endpoint == 'register':
                            logging.info(f'REGISTRO SUCESSO: {email} - IP: {client_ip} - Duração: {duration:.3f}s')
                        elif status_code == 401:
                            logging.warning(f'LOGIN FALHA: {email} - IP: {client_ip} - User-Agent: {user_agent}')
                        elif status_code == 400:
                            logging.warning(f'DADOS INVÁLIDOS: {email} - IP: {client_ip} - Rota: {request.endpoint}')
                        elif status_code in [423, 429]:
                            logging.critical(f'BLOQUEIO ATIVADO: {email} - IP: {client_ip} - Status: {status_code}')
                    
                    return response
                    
                except Exception as e:
                    logging.error(f'ERRO na rota {request.endpoint}: {str(e)} - IP: {client_ip}')
                    raise
                    
            return decorated_function
        return decorator

# Função utilitária para limpar dados antigos (chame periodicamente)
def cleanup_security_data():
    """
    Limpa dados antigos dos storages de segurança
    Chame esta função periodicamente (ex: via cron job)
    """
    current_time = time.time()
    
    # Limpar rate limits antigos
    for ip in list(rate_limit_storage.keys()):
        rate_limit_storage[ip] = [
            timestamp for timestamp in rate_limit_storage[ip]
            if current_time - timestamp < RATE_LIMIT_WINDOW
        ]
        if not rate_limit_storage[ip]:
            del rate_limit_storage[ip]
    
    # Limpar dados de brute force antigos
    for key in list(brute_force_storage.keys()):
        brute_force_storage[key] = [
            timestamp for timestamp in brute_force_storage[key]
            if current_time - timestamp < BRUTE_FORCE_WINDOW
        ]
        if not brute_force_storage[key]:
            del brute_force_storage[key]
    
    logging.info("Limpeza de dados de segurança concluída")

# Função para verificar status de bloqueio (útil para debugging)
def get_security_status(email=None, ip=None):
    """
    Retorna status atual de segurança para email/IP
    """
    current_time = time.time()
    status = {
        'email_attempts': 0,
        'ip_attempts': 0,
        'combo_attempts': 0,
        'blocked': False,
        'time_until_unblock': 0
    }
    
    if email:
        email_key = f"email:{email.lower().strip()}"
        status['email_attempts'] = len([
            t for t in brute_force_storage.get(email_key, [])
            if current_time - t < BRUTE_FORCE_WINDOW
        ])
    
    if ip:
        ip_key = f"ip:{ip}"
        status['ip_attempts'] = len([
            t for t in brute_force_storage.get(ip_key, [])
            if current_time - t < BRUTE_FORCE_WINDOW
        ])
    
    if email and ip:
        combo_key = f"combo:{email.lower().strip()}:{ip}"
        status['combo_attempts'] = len([
            t for t in brute_force_storage.get(combo_key, [])
            if current_time - t < BRUTE_FORCE_WINDOW
        ])
    
    # Verificar se está bloqueado
    if (status['email_attempts'] >= BRUTE_FORCE_ATTEMPTS or 
        status['ip_attempts'] >= BRUTE_FORCE_ATTEMPTS * 2 or
        status['combo_attempts'] >= BRUTE_FORCE_ATTEMPTS):
        status['blocked'] = True
        
        # Calcular tempo restante de bloqueio
        oldest_attempt = current_time
        for key in [f"email:{email}", f"ip:{ip}", f"combo:{email}:{ip}"]:
            if key in brute_force_storage and brute_force_storage[key]:
                oldest_attempt = min(oldest_attempt, min(brute_force_storage[key]))
        
        status['time_until_unblock'] = max(0, BRUTE_FORCE_WINDOW - (current_time - oldest_attempt))
    
    return status

#
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

brasilia_tz = pytz.timezone('America/Sao_Paulo')

logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(brasilia_tz))
    is_active = db.Column(db.Boolean, default=True)
    is_anonymized = db.Column(db.Boolean, default=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@SecurityDecorator.rate_limit(max_requests=3, window=300)  # 3 tentativas por 5 min
@SecurityDecorator.input_validation()
@SecurityDecorator.security_headers()
@SecurityDecorator.enhanced_logging()
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form.get('role', 'user')
        
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Usuário já existe"}), 400
        
        new_user = User(email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        logging.info(f'Novo usuário registrado: {email} com papel: {role}')
        return jsonify({"success": "Usuário registrado com sucesso"}), 200
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@SecurityDecorator.rate_limit(max_requests=5, window=300)  # 5 tentativas por 5 min
@SecurityDecorator.brute_force_protection(max_attempts=3, window=900)  # 3 tentativas por 15 min
@SecurityDecorator.input_validation()
@SecurityDecorator.security_headers()
@SecurityDecorator.enhanced_logging()
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['role'] = user.role
        session['email'] = user.email
        logging.info(f'Login bem-sucedido: {email}')
        return jsonify({"success": "Login bem-sucedido", "role": user.role}), 200
    
    logging.warning(f'Tentativa de login falha: {email}')
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    return render_template('dashboard.html')

@app.route('/user_info')
def user_info():
    if 'user_id' not in session:
        return jsonify({"error": "Não autenticado"}), 401
    
    # Buscar usuário do banco de dados
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404
    
    user_data = {
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat()  # Converte para string ISO
    }
    return jsonify(user_data)
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html')
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='reset-password')
            reset_link = url_for('reset_token', token=token, _external=True)
            logging.info(f'Link de reset gerado para: {email}')
            return jsonify({"success": "Link de reset enviado", "link": reset_link})
        return jsonify({"error": "Usuário não encontrado"}), 404

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except:
        return render_template('error.html', message="Token expirado ou inválido")
    
    if request.method == 'GET':
        return render_template('reset_form.html', token=token, email=email)
    
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        new_password = generate_password_hash(request.form['password'])
        user.password = new_password
        db.session.commit()
        return jsonify({"success": "Senha redefinida com sucesso"})

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({"error": "Não autenticado"}), 401
    
    #user = User.query.get(session['user_id'])
    user = db.session.get(User, session['user_id'])
    user.email = f'anonymous_{user.id}@example.com'
    user.password = ''
    user.is_active = False
    user.is_anonymized = True
    db.session.commit()
    logging.info(f'Conta anonimizada: {user.id}')
    session.clear()
    return jsonify({"success": "Conta excluída e dados anonimizados"})

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        return render_template('error.html', message="Acesso negado")
    
    users = User.query.filter_by(is_anonymized=False).all()

    # Dados para a tabela
    users_data = [
        {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "active": user.is_active
        }
        for user in users
    ]

    # Estatísticas
    total_users = len(users)
    admin_count = sum(1 for user in users if user.role == 'admin')
    active_users = sum(1 for user in users if user.is_active)

    return render_template(
        'admin.html',
        users=users_data,
        total_users=total_users,
        admin_count=admin_count,
        active_users=active_users
    )

@app.route('/api/users')
def api_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "Acesso negado"}), 403
    
    users = User.query.filter_by(is_anonymized=False).all()
    users_data = [{"id": user.id, "email": user.email, "role": user.role, "active": user.is_active} for user in users]
    return jsonify(users_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)