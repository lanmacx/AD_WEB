from flask import Flask, request, render_template, redirect, url_for, flash, session
from functools import wraps
import os
from dotenv import load_dotenv
from config import *
from datetime import datetime, timedelta, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, AUTO_BIND_NO_TLS

load_dotenv()

# Função para verificar login
def verificar_login(username, password):
    try:
        server = Server(SERVIDOR_AD, port=PORTA_AD, get_info=ALL)
        conn = Connection(server, user=f"{username}@{dominio_ad}", password=password,
                          authentication=SIMPLE)
        if conn.bind():
            print(f"Usuário {username} autenticado com sucesso.")
            conn.unbind()
            return True
        else:
            print(f"Falha na autenticação do usuário {username}.")
            return False
    except Exception as e:
        print(f"Erro de autenticação: {str(e)}")
        return False

def verificar_grupo(username, grupo_ti, grupo_rh):
    try:
        server = Server(LDAP_SERVER, port=PORT_SSL, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad, authentication=SIMPLE)
        
        if not conn.bind():
            print(f"Falha na conexão ao servidor LDAP ao verificar grupo para o usuário {username}.")
            return False

        search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
        conn.search(base_dn, search_filter, attributes=['memberOf'])

        if conn.entries:
            user_entry = conn.entries[0]
            member_of = user_entry['memberOf'].values

            grupoRH = f"CN={grupo_rh},OU=Departamentos,OU=Security,OU=Groups,OU=UR_SPO,{base_dn}"
            grupoTI = f"CN={grupo_ti},OU=Security,OU=Groups,OU=UR_SPO,{base_dn}"


            if grupoTI in member_of:
                print(f"Usuário {username} pertence ao grupo {grupoTI}.")
                return "TI"
            if grupoRH in member_of:
                print(f"Usuário {username} pertence ao grupo {grupoRH}.")
                return "RH"
        else:
            print(f"Usuário {username} não encontrado no AD.")
            return ""
    except Exception as e:
        print(f"Erro ao verificar grupo: {str(e)}")
        return ""

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def verificar_expiracao_senha(nome_usuario):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')
        base_dn = os.getenv('BASE_DN')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)
        conn.search(search_base=base_dn,
                    search_filter=f'(&(objectClass=user)(sAMAccountName={nome_usuario}))',
                    search_scope=SUBTREE,
                    attributes=['cn', 'displayName', 'distinguishedName', 'pwdLastSet', 'lockoutTime'])

        if len(conn.entries) == 0:
            return "Usuário não encontrado no Active Directory.", None, False, False, False

        result = conn.entries[0]
        pwd_last_set = result['pwdLastSet'].value

        if isinstance(pwd_last_set, datetime):
            pwd_last_set = int(pwd_last_set.timestamp() * 10000000) + 116444736000000000

        last_set_date = datetime.fromtimestamp(pwd_last_set / 10000000 - 11644473600).replace(tzinfo=timezone.utc)

        # Verificando a data de expiração da senha
        expiracao = last_set_date + timedelta(days=90)  # Senha expira em 90 dias
        dias_restantes = (expiracao - datetime.now(timezone.utc)).days

        expirou = dias_restantes <= 0

        # Verificando se o usuário está bloqueado
        bloqueado = False
        if 'lockoutTime' in result and result['lockoutTime'].value:
            if result['lockoutTime'].value > datetime(1601, 1, 1, tzinfo=timezone.utc):
                bloqueado = True

        return f'Senha expira em {expiracao.strftime("%d/%m/%Y %H:%M")}', expiracao, True, expirou, bloqueado

    except Exception as e:
        return str(e), None, False, False, False

def alterar_senha_usuario(nome_usuario, nova_senha):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')
        base_dn = os.getenv('BASE_DN')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)

        user_dn = None
        conn.search(search_base=base_dn,
                    search_filter=f'(&(objectClass=user)(sAMAccountName={nome_usuario}))',
                    search_scope=SUBTREE,
                    attributes=['distinguishedName'])
        
        if len(conn.entries) > 0:
            user_dn = conn.entries[0].distinguishedName.value
        
        if not user_dn:
            return "Usuário não encontrado no Active Directory.", False

        conn.extend.microsoft.modify_password(user_dn, nova_senha)
        if conn.result['result'] == 0:
            return "Senha alterada com sucesso.", True
        else:
            return conn.result['description'], False

    except Exception as e:
        return str(e), False

def desbloquear_usuario(nome_usuario):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')
        base_dn = os.getenv('BASE_DN')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)

        user_dn = None
        conn.search(search_base=base_dn,
                    search_filter=f'(&(objectClass=user)(sAMAccountName={nome_usuario}))',
                    search_scope=SUBTREE,
                    attributes=['distinguishedName'])
        
        if len(conn.entries) > 0:
            user_dn = conn.entries[0].distinguishedName.value
        
        if not user_dn:
            return "Usuário não encontrado no Active Directory.", False

        conn.modify(user_dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]})
        if conn.result['result'] == 0:
            return "Usuário desbloqueado com sucesso.", True
        else:
            return conn.result['description'], False

    except Exception as e:
        return str(e), False
 
def user_details(username):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')
        base_dn = os.getenv('BASE_DN')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)
        search_filter = f'(sAMAccountName={username})'
        conn.search(base_dn, search_filter, attributes=['cn', 'dateOfBirth', 'extensionAttribute1', 'extensionAttribute2'])

        if conn.entries:
            user = conn.entries[0]
            print(f"CN: {user.cn}")
            print(f"Date of Birth: {user.dateOfBirth}")
            print(f"Extension Attribute 1: {user.extensionAttribute1}")
            print(f"Extension Attribute 2: {user.extensionAttribute2}")
            return user
        else:
            print("Usuário não encontrado.")
            return None
    except Exception as e:
        return str(e), False