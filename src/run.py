from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import logging
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_anonymized = db.Column(db.Boolean, default=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
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
    
    user_data = {
        "email": session.get('email'),
        "role": session.get('role')
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
    users_data = [{"id": user.id, "email": user.email, "role": user.role, "active": user.is_active} for user in users]
    return render_template('admin.html', users=users_data)

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