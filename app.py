#!/usr/bin/env python3
"""
DATCHILD - PLATAFORMA DE ANÁLISE DE VULNERABILIDADES
Versão 1.0.0 - Production Ready
Desenvolvido para empresas em Angola

Autor: Datchild.ao
Data: 2025
Preço: 15.000.000 Kz
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import json
import os
import re
import hashlib
import uuid
import subprocess
import requests
from datetime import datetime, timedelta
from functools import wraps
from config import config
import logging

# ==================== INICIALIZAÇÃO ====================

app = Flask(__name__)
app.config.from_object(config)
CORS(app)

# Base de Dados
db = SQLAlchemy(app)

# Logging
logging.basicConfig(level=getattr(logging, app.config['LOG_LEVEL']))
logger = logging.getLogger(__name__)

# ==================== MODELOS ====================

class Usuario(db.Model):
    """Modelo de utilizador"""
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    empresa = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    nif = db.Column(db.String(20), unique=True, nullable=False)
    token = db.Column(db.String(100), unique=True)
    plano = db.Column(db.String(20), default='teste')
    scans_restantes = db.Column(db.Integer, default=2)
    ativo = db.Column(db.Boolean, default=True)
    admin = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    scans = db.relationship('Scan', backref='usuario', lazy=True, cascade='all, delete-orphan')
    pagamentos = db.relationship('Pagamento', backref='usuario', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, senha):
        """Encripta senha"""
        self.senha_hash = generate_password_hash(senha)
    
    def check_password(self, senha):
        """Verifica senha"""
        return check_password_hash(self.senha_hash, senha)
    
    def gerar_token(self):
        """Gera token JWT"""
        payload = {
            'user_id': self.id,
            'email': self.email,
            'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])
    
    def para_dict(self):
        """Converte para dicionário"""
        return {
            'id': self.id,
            'nome': self.nome,
            'email': self.email,
            'empresa': self.empresa,
            'telefone': self.telefone,
            'plano': self.plano,
            'scans_restantes': self.scans_restantes,
            'verified': self.verified,
            'admin': self.admin,
            'criado_em': self.criado_em.isoformat()
        }

class Scan(db.Model):
    """Modelo de scan de vulnerabilidades"""
    __tablename__ = 'scans'
    
    id = db.Column(db.String(50), primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    alvo = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pendente')  # pendente, em_andamento, concluido, erro
    progresso = db.Column(db.Integer, default=0)
    portas_abertas = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer)
    risco_nivel = db.Column(db.String(20))  # Baixo, Médio, Alto, Crítico
    vulnerabilidades = db.Column(db.Text)  # JSON
    analise_ia = db.Column(db.Text)  # JSON
    resultados = db.Column(db.Text)  # JSON
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    completado_em = db.Column(db.DateTime)
    
    def para_dict(self):
        """Converte para dicionário"""
        return {
            'id': self.id,
            'alvo': self.alvo,
            'status': self.status,
            'progresso': self.progresso,
            'portas_abertas': self.portas_abertas,
            'risk_score': self.risk_score,
            'risco_nivel': self.risco_nivel,
            'vulnerabilidades': json.loads(self.vulnerabilidades) if self.vulnerabilidades else [],
            'analise_ia': json.loads(self.analise_ia) if self.analise_ia else {},
            'criado_em': self.criado_em.isoformat(),
            'completado_em': self.completado_em.isoformat() if self.completado_em else None
        }

class Pagamento(db.Model):
    """Modelo de pagamento"""
    __tablename__ = 'pagamentos'
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    valor = db.Column(db.Integer, nullable=False)  # Em Kz
    tipo = db.Column(db.String(20), nullable=False)  # stripe, multicaixa, manual
    plano = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pendente')  # pendente, concluido, recusado
    referencia = db.Column(db.String(255))
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    confirmado_em = db.Column(db.DateTime)

class Log(db.Model):
    """Modelo de logs de auditoria"""
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    acao = db.Column(db.String(100), nullable=False)
    detalhes = db.Column(db.Text)
    ip = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== DECORADORES ====================

def requer_autenticacao(f):
    """Decorador para requerer autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'status': 'erro', 'mensagem': 'Token não fornecido'}), 401
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
            usuario = Usuario.query.get(payload['user_id'])
            if not usuario or not usuario.ativo:
                return jsonify({'status': 'erro', 'mensagem': 'Utilizador inválido'}), 401
            request.usuario = usuario
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'erro', 'mensagem': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 'erro', 'mensagem': 'Token inválido'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def requer_admin(f):
    """Decorador para requerer privilégios de admin"""
    @wraps(f)
    @requer_autenticacao
    def decorated_function(*args, **kwargs):
        if not request.usuario.admin:
            return jsonify({'status': 'erro', 'mensagem': 'Acesso negado'}), 403
        return f(*args, **kwargs)
    
    return decorated_function

def registar_log(acao, detalhes=''):
    """Registar ação em logs"""
    try:
        usuario_id = request.usuario.id if hasattr(request, 'usuario') else None
        log = Log(
            usuario_id=usuario_id,
            acao=acao,
            detalhes=detalhes,
            ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Erro ao registar log: {e}")

# ==================== UTILITÁRIOS ====================

def validar_ip_dominio(alvo):
    """Valida se é um IP ou domínio válido"""
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    return bool(ip_pattern.match(alvo) or domain_pattern.match(alvo))

def validar_ip_privado(ip):
    """Verifica se é um IP privado (segurança)"""
    private_ranges = [
        '127.0.0.1',
        '192.168.',
        '10.',
        '172.16.',
        '172.17.',
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',
    ]
    
    return any(ip.startswith(r) for r in private_ranges)

# ==================== ROTAS - AUTENTICAÇÃO ====================

@app.route('/api/registar', methods=['POST'])
def registar():
    """Registar novo utilizador"""
    dados = request.get_json() or {}
    
    # Validar dados
    campos_obrigatorios = ['nome', 'email', 'senha', 'empresa', 'telefone', 'nif']
    if not all(campo in dados for campo in campos_obrigatorios):
        return jsonify({'status': 'erro', 'mensagem': 'Campos obrigatórios faltando'}), 400
    
    # Verificar email duplicado
    if Usuario.query.filter_by(email=dados['email']).first():
        return jsonify({'status': 'erro', 'mensagem': 'Email já registado'}), 409
    
    try:
        usuario = Usuario(
            nome=dados['nome'],
            email=dados['email'],
            empresa=dados['empresa'],
            telefone=dados['telefone'],
            nif=dados['nif'],
            plano='teste',
            scans_restantes=app.config['PLANOS']['teste']['scans']
        )
        usuario.set_password(dados['senha'])
        usuario.token = usuario.gerar_token()
        
        db.session.add(usuario)
        db.session.commit()
        
        registar_log('registar', f'Novo utilizador: {usuario.email}')
        
        return jsonify({
            'status': 'ok',
            'token': usuario.token,
            'usuario': usuario.para_dict(),
            'mensagem': 'Conta criada com sucesso!'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao registar: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro ao criar conta'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login de utilizador"""
    dados = request.get_json() or {}
    
    email = dados.get('email', '')
    senha = dados.get('senha', '')
    
    usuario = Usuario.query.filter_by(email=email).first()
    
    if not usuario or not usuario.check_password(senha):
        registar_log('login_falho', f'Login falhado: {email}')
        return jsonify({'status': 'erro', 'mensagem': 'Email ou senha incorretos'}), 401
    
    if not usuario.ativo:
        return jsonify({'status': 'erro', 'mensagem': 'Conta desativada'}), 403
    
    usuario.token = usuario.gerar_token()
    db.session.commit()
    
    registar_log('login', f'Login bem-sucedido: {email}')
    
    return jsonify({
        'status': 'ok',
        'token': usuario.token,
        'usuario': usuario.para_dict()
    }), 200

# ==================== ROTAS - SCANS ====================

@app.route('/api/novo_scan', methods=['POST'])
@requer_autenticacao
def novo_scan():
    """Criar novo scan"""
    dados = request.get_json() or {}
    alvo = dados.get('alvo', '').strip()
    
    # Validar alvo
    if not alvo or not validar_ip_dominio(alvo):
        return jsonify({'status': 'erro', 'mensagem': 'Alvo inválido (IP ou domínio)'}), 400
    
    # Verificar se é IP privado
    try:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', alvo) and validar_ip_privado(alvo):
            return jsonify({'status': 'erro', 'mensagem': 'Não é permitido escanear IPs privados'}), 403
    except:
        pass
    
    # Verificar scans restantes
    if request.usuario.plano == 'teste' and request.usuario.scans_restantes <= 0:
        return jsonify({'status': 'erro', 'mensagem': 'Scans esgotados. Adquira um plano.'}), 429
    
    # Verificar rate limiting (5 scans/hora)
    scans_ultima_hora = Scan.query.filter(
        Scan.usuario_id == request.usuario.id,
        Scan.criado_em >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    if scans_ultima_hora >= app.config['MAX_SCANS_POR_HORA']:
        return jsonify({'status': 'erro', 'mensagem': 'Limite de scans por hora atingido'}), 429
    
    try:
        scan_id = f"SCAN-{int(datetime.utcnow().timestamp())}-{uuid.uuid4().hex[:8]}"
        
        scan = Scan(
            id=scan_id,
            usuario_id=request.usuario.id,
            alvo=alvo,
            status='pendente'
        )
        
        # Decrementar scans se em plano teste
        if request.usuario.plano == 'teste':
            request.usuario.scans_restantes -= 1
        
        db.session.add(scan)
        db.session.commit()
        
        registar_log('novo_scan', f'Scan criado: {alvo}')
        
        # TODO: Executar scan em background (usar Celery ou threading)
        
        return jsonify({
            'status': 'ok',
            'scan_id': scan_id,
            'mensagem': 'Scan iniciado!'
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar scan: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro ao iniciar scan'}), 500

@app.route('/api/scans', methods=['GET'])
@requer_autenticacao
def listar_scans():
    """Listar scans do utilizador"""
    scans = Scan.query.filter_by(usuario_id=request.usuario.id).order_by(Scan.criado_em.desc()).all()
    
    return jsonify({
        'status': 'ok',
        'scans': [scan.para_dict() for scan in scans]
    }), 200

@app.route('/api/scan/<scan_id>', methods=['GET'])
@requer_autenticacao
def obter_scan(scan_id):
    """Obter detalhes de um scan específico"""
    scan = Scan.query.filter_by(id=scan_id, usuario_id=request.usuario.id).first()
    
    if not scan:
        return jsonify({'status': 'erro', 'mensagem': 'Scan não encontrado'}), 404
    
    return jsonify({
        'status': 'ok',
        'scan': scan.para_dict()
    }), 200

# ==================== ROTAS - ADMIN ====================

@app.route('/api/admin/estatisticas', methods=['GET'])
@requer_admin
def admin_estatisticas():
    """Obter estatísticas do sistema (ADMIN)"""
    total_usuarios = Usuario.query.count()
    total_scans = Scan.query.count()
    scans_completos = Scan.query.filter_by(status='concluido').count()
    scans_hoje = Scan.query.filter(
        Scan.criado_em >= datetime.utcnow().date()
    ).count()
    
    return jsonify({
        'status': 'ok',
        'estatisticas': {
            'total_usuarios': total_usuarios,
            'total_scans': total_scans,
            'scans_completos': scans_completos,
            'scans_hoje': scans_hoje,
            'timestamp': datetime.utcnow().isoformat()
        }
    }), 200

@app.route('/api/admin/usuarios', methods=['GET'])
@requer_admin
def admin_usuarios():
    """Listar todos os utilizadores (ADMIN)"""
    usuarios = Usuario.query.all()
    
    return jsonify({
        'status': 'ok',
        'usuarios': [u.para_dict() for u in usuarios]
    }), 200

# ==================== ROTAS - INFORMAÇÕES ====================

@app.route('/api/info', methods=['GET'])
def info():
    """Informações sobre o Datchild"""
    return jsonify({
        'nome': app.config['COMPANY_NAME'],
        'versao': '1.0.0',
        'whatsapp': app.config['COMPANY_WHATSAPP'],
        'telefone': app.config['COMPANY_PHONE'],
        'email': app.config['COMPANY_EMAIL'],
        'iban': app.config['COMPANY_IBAN'],
        'preco': app.config['COMPANY_PRICE'],
        'planos': app.config['PLANOS']
    }), 200

@app.route('/api/status', methods=['GET'])
def status():
    """Status do servidor"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.utcnow().isoformat(),
        'versao': '1.0.0',
        'ambiente': app.config.get('FLASK_ENV', 'unknown')
    }), 200

# ==================== ROTAS - PÁGINAS ====================

@app.route('/')
def index():
    """Página inicial"""
    return jsonify({
        'mensagem': 'Bem-vindo ao Datchild - Análise de Vulnerabilidades para Empresas Angolanas',
        'acesso': {
            'registar': '/api/registar',
            'login': '/api/login',
            'info': '/api/info',
            'status': '/api/status'
        }
    }), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'erro', 'mensagem': 'Recurso não encontrado'}), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Erro interno do servidor: {error}")
    return jsonify({'status': 'erro', 'mensagem': 'Erro interno do servidor'}), 500

@app.errorhandler(429)
def rate_limit(error):
    return jsonify({'status': 'erro', 'mensagem': 'Limite de requisições atingido'}), 429

# ==================== INICIALIZAÇÃO ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("""
    ╔═══════════════════════════════════════════╗
    ║         DATCHILD - VERSÃO 1.0.0           ║
    ║  Análise de Vulnerabilidades Angola 🇦🇴   ║
    ╚═══════════════════════════════════════════╝
    
    🚀 Servidor iniciando...
    """)
    
    app.run(
        host=app.config['HOST'],
        port=app.config['PORTA_WEB'],
        debug=app.config['DEBUG']
    )
