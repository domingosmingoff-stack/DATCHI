#!/usr/bin/env python3
"""
DATCHILD - Configurações Seguras
"""

import os
from dotenv import load_dotenv
from datetime import timedelta

# Carregar variáveis de ambiente
load_dotenv()

class Config:
    """Configurações base"""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('FLASK_DEBUG', False)
    
    # Servidor
    PORTA_WEB = int(os.getenv('PORTA_WEB', 5000))
    PORTA_WS = int(os.getenv('PORTA_WS', 8080))
    PORTA_API = int(os.getenv('PORTA_API', 9090))
    HOST = '0.0.0.0'
    
    # Base de Dados
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///datchild.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # APIs Externas
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')
    VULNERS_API_KEY = os.getenv('VULNERS_API_KEY')
    STRIPE_SECRET = os.getenv('STRIPE_SECRET_KEY')
    STRIPE_PUBLIC = os.getenv('STRIPE_PUBLISHABLE_KEY')
    
    # Twilio
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    TWILIO_WHATSAPP_NUMBER = os.getenv('TWILIO_WHATSAPP_NUMBER')
    
    # Email
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_EMAIL = os.getenv('SMTP_EMAIL')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    
    # Empresa
    COMPANY_NAME = os.getenv('COMPANY_NAME', 'Datchild')
    COMPANY_WHATSAPP = os.getenv('COMPANY_WHATSAPP', '952602199')
    COMPANY_PHONE = os.getenv('COMPANY_PHONE', '973127839')
    COMPANY_EMAIL = os.getenv('COMPANY_EMAIL', 'suporte@datchild.ao')
    COMPANY_IBAN = os.getenv('COMPANY_IBAN', '0055.0000.7672.5016.1011.6')
    COMPANY_PRICE = int(os.getenv('COMPANY_PRICE', 15000000))
    
    # Nmap
    NMAP_PATH = os.getenv('NMAP_PATH', 'nmap')
    
    # Segurança
    MAX_SCANS_POR_HORA = int(os.getenv('MAX_SCANS_POR_HORA', 5))
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 10485760))
    ALLOWED_IP_RANGES = os.getenv('ALLOWED_IP_RANGES', '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12').split(',')
    
    # JWT
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
    JWT_ALGORITHM = 'HS256'
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Planos de Preço (em Kz - Kwanza angolano)
    PLANOS = {
        'teste': {
            'nome': 'Teste',
            'preco': 0,
            'scans': 2,
            'duracao_dias': 7,
            'descricao': '2 scans grátis para testar'
        },
        'basico': {
            'nome': 'Básico',
            'preco': 50000,
            'scans': 5,
            'duracao_dias': 30,
            'descricao': '5 scans por mês + suporte por email'
        },
        'profissional': {
            'nome': 'Profissional',
            'preco': 100000,
            'scans': 15,
            'duracao_dias': 30,
            'descricao': '15 scans por mês + relatórios em PDF + suporte prioritário'
        },
        'enterprise': {
            'nome': 'Enterprise',
            'preco': 200000,
            'scans': 999999,
            'duracao_dias': 30,
            'descricao': 'Scans ilimitados + suporte 24/7 WhatsApp + API access'
        }
    }
    
    # Portas comuns a escanear
    PORTAS_COMUNS = [
        21, 22, 25, 53, 80, 110, 143, 443, 445, 465,
        587, 993, 995, 1433, 3306, 3389, 5432, 5900,
        8000, 8080, 8443, 8888, 9000, 9090
    ]

class DevelopmentConfig(Config):
    """Configuração para desenvolvimento"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Configuração para produção"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Configuração para testes"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Selecionar configuração
config_name = os.getenv('FLASK_ENV', 'development')
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}.get(config_name, DevelopmentConfig)
