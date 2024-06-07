from flask import Flask, request, render_template, redirect, url_for, flash, session, get_flashed_messages
from functools import wraps
import os
from dotenv import load_dotenv
from services import verificar_login, verificar_expiracao_senha, alterar_senha_usuario, desbloquear_usuario, verificar_grupo, user_details
from config import *
from datetime import datetime, timedelta, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, AUTO_BIND_NO_TLS

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessário para usar flash messages
load_dotenv()  # Carregar variáveis de ambiente do arquivo .env


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        print(session['permissao'])
        if session['permissao'] == 'TI': 
            return redirect(url_for('index'))
        else:
            return redirect(url_for('rh'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        grupo_ti = os.getenv('grupo_ti')
        grupo_rh = os.getenv('grupo_rh')
        
        if verificar_login(username, password):
            
            department = verificar_grupo(username, grupo_ti, grupo_rh) 
            if department == 'TI':
                session['username'] = username
                session['departamento'] = department
                session['permissao'] = 'TI'
                # flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            elif department:
                session['departamento'] = department
                session['username'] = username
                session['permissao'] = 'RH'
                # flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('rh'))
            else:
                flash('Usuário não pertence ao grupo corresponde.', 'error')
                
        else:
            flash('Nome de usuário ou senha inválidos.', 'error')
       
    return render_template('index.html')
    
@app.route('/logout')
def logout():
    session.pop('username', None)
    # flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' in session:
        print(session['permissao'])
        if session['permissao'] == 'TI': 
            return render_template('index.html')
        else:
            return redirect(url_for('rh'))
    else:
        return redirect(url_for('login'))
        

@app.route('/rh')
def rh():
    return render_template('rh.html')

@app.route('/users')
def users():
    if 'username' in session:
        print(session['permissao'])
        if session['permissao'] == 'TI': 
            return render_template('users.html')
        else:
            return redirect(url_for('rh'))
    

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if query:
        resultado, expiracao, encontrado, expirou, bloqueado = verificar_expiracao_senha(query)
        if encontrado:
            expiracao_formatada = expiracao.strftime(f"%d/%m/%Y às %H:%Mhs")
            expiracao_status = "expirada" if expirou else "não expirada"
            return render_template('resultado.html', username=query, expiracao=expiracao_formatada, status=expiracao_status, bloqueado=bloqueado)
        else:
            flash("Usuário não encontrado no Active Directory.", 'error')
            return render_template('index.html')
    else:
        flash("Por favor, forneça um nome de usuário para pesquisa.", 'error')
        return redirect(url_for('index'))
    
@app.route('/user.details', methods=['GET'])
def search_user():
    query = request.args.get('query')
    page = request.args.get('page', 1, type=int)  # Número da página atual
    per_page = 4  # Número de resultados por página
    
    if not query:
        flash("Por favor, forneça um nome de usuário para pesquisa.", 'error')
        return redirect(url_for('search_user'))
        
    # Conectar ao servidor AD
    server = Server(LDAP_SERVER, port=PORT_SSL, use_ssl=True, get_info=ALL)
    conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad, auto_bind=True)
    
    search_filter = f'(cn={query}*)'
    conn.search(base_dn, search_filter, attributes=['cn', 'extensionAttribute1', 'extensionAttribute2', 'department', 'physicalDeliveryOfficeName', 
                                                    'title', 'telephoneNumber'])

    if conn.entries:
        users = conn.entries
        
        if(len(users)==1):
            user = users[0]
            user_info = {
                "cn": str(user.cn),
                "extensionAttribute1": str(user.extensionAttribute1),
                "extensionAttribute2": str(user.extensionAttribute2),
                "department": str(user.department),
                "physicalDeliveryOfficeName": str(user.physicalDeliveryOfficeName), 
                "title": str(user.title),
                "telephoneNumber": str(user.telephoneNumber), 
                }
            
            return render_template('update.html', user=user_info)
        else:            
            return render_template('rh.html', users=users)
            
    else:
        flash("Usuário não encontrado no Active Directory.", 'error')
        return render_template('rh.html', user=None)
    
@app.route('/change-password', methods=['POST'])
def change_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash("As senhas não coincidem.", 'error')
        return redirect(url_for('search', query=username))

    resultado, sucesso = alterar_senha_usuario(username, new_password)
    if sucesso:
        flash(f"A senha do usuário {username} foi trocada com sucesso.", 'success')
    else:
        flash(f"Erro ao trocar a senha: {resultado}", 'error')

    return redirect(url_for('index'))

@app.route('/user.update', methods=['POST'])
def update_user():
    cn = request.form.get('cn')
    extensionAttribute1 = request.form.get('extensionAttribute1')
    extensionAttribute2 = request.form.get('extensionAttribute2')
    department = request.form.get('department')
    physicalDeliveryOfficeName = request.form.get('physicalDeliveryOfficeName')
    title = request.form.get('title')
    telephoneNumber = request.form.get('telephoneNumber')

    # Conectar ao servidor AD
    server = Server(LDAP_SERVER, port=PORT_SSL, use_ssl=True, get_info=ALL)
    conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad, auto_bind=True)
    
    search_filter = f'(cn={cn})'
    conn.search(base_dn, search_filter, attributes=['cn'])

    if conn.entries:
        user_dn = conn.entries[0].entry_dn
        conn.modify(user_dn, {
            'extensionAttribute1': [(MODIFY_REPLACE, [extensionAttribute1])],
            'extensionAttribute2': [(MODIFY_REPLACE, [extensionAttribute2])],
            'department': [(MODIFY_REPLACE, [department])],
            'physicalDeliveryOfficeName': [(MODIFY_REPLACE, [physicalDeliveryOfficeName])],
            'title': [(MODIFY_REPLACE, [title])],
            'telephoneNumber': [(MODIFY_REPLACE, [telephoneNumber])],
        })
        flash("Detalhes do usuário atualizados com sucesso.", 'success')
    else:
        flash("Erro ao encontrar o usuário para atualização.", 'error')

    return redirect(url_for('rh'))

@app.route('/unlock-user', methods=['POST'])
def unlock_user():
    username = request.form.get('username')
    resultado, sucesso = desbloquear_usuario(username)
    if sucesso:
        flash(f"O usuário {username} foi desbloqueado com sucesso.", 'success')
    else:
        flash(f"Erro ao desbloquear o usuário: {resultado}", 'error')

    return render_template('rh.html', flash_messages=get_flashed_messages(with_categories=True))
   
@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        primeiro_nome = request.form['primeiro_nome']
        sobrenome = request.form['sobrenome']
        logon = request.form['logon']
        email = logon + '@amchambrasil.com.br'  # Adiciona o domínio ao logon para criar o userPrincipalName
        sAMAccountName = request.form['logon_sAMAccountName']
        password = request.form['password']
        regional = request.form['regional']
        nascimento = request.form['dateofbrith']
      
        # Atributos adicionais
        physicalDeliveryOfficeName = request.form['physicalDeliveryOfficeName']
        st = request.form['st']
        company = request.form['company']
        description = request.form['description']
        title = request.form['title']
        department = request.form['department']
        
        print(f"Campos do formulário: {request.form}")

        # Validação dos campos
        if not all([primeiro_nome, sobrenome, logon, sAMAccountName, email, password, regional]):
            flash('Por favor, preencha todos os campos.', 'error')
            return redirect(url_for('index'))

        # Conectando ao servidor AD        
        print(f"Tentando conectar ao servidor AD: {LDAP_SERVER}:{PORT_SSL}")
        server = Server(LDAP_SERVER, port=PORT_SSL, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=True, authentication=SIMPLE, raise_exceptions=False)

        if not conn.bind():           
            print(f"Falha na conexão LDAP: {conn.result}")
            flash(f"Erro de conexão com o servidor AD: {conn.result['description']}", 'error')
            return redirect(url_for('index'))

        print("Conexão LDAP estabelecida com sucesso.")

        # Informações do novo usuário
        user_dn = f'CN={primeiro_nome} {sobrenome},OU=Standard,OU=Users,OU={regional},DC=amchambr,DC=com,DC=br'
        user_attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': f'{primeiro_nome} {sobrenome}',
            'sn': sobrenome,
            'givenName': primeiro_nome,
            'sAMAccountName': sAMAccountName,
            'userPrincipalName': f'{sAMAccountName}@amchambr.com.br',  # Utiliza o email como userPrincipalName
            'displayName': f'{primeiro_nome} {sobrenome}',
            'mail': email,
            'extensionAttribute1': nascimento,
            'userAccountControl': 512,  # Conta normal
            'unicodePwd': f'"{password}"'.encode('utf-16-le'),
            # Atributos adicionais
            'physicalDeliveryOfficeName': physicalDeliveryOfficeName,
            'st': st,
            'company': company,
            'description': description,
            'title': title,
            'department': department,
        }

        # Criando o usuário no AD
        if not conn.add(user_dn, attributes=user_attributes):
            print(f"Erro ao adicionar usuário no AD: {conn.result}")
            flash(f"Erro ao criar usuário: {conn.result['description']}", 'error')
            return redirect(url_for('index'))

        # Adicionando a senha separadamente
        if not conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [f'"{password}"'.encode('utf-16-le')])]}):
            print(f"Erro ao definir senha do usuário: {conn.result}")
            flash(f"Erro ao definir senha do usuário: {conn.result['description']}", 'error')
            return redirect(url_for('index'))
        
        
        # Se tudo ocorreu bem até aqui, exibir mensagem de sucesso
        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        print(f"Erro ao criar usuário: {str(e)}")
        flash(f"Erro ao criar usuário: {str(e)}", 'error')
        return redirect(url_for('index'))
       
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)