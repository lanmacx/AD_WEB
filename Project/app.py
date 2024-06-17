import logging
from flask import Flask, request, render_template, redirect, url_for, flash, session, get_flashed_messages, send_from_directory
from functools import wraps
import os
from dotenv import load_dotenv
from services import verificar_login, verificar_expiracao_senha, alterar_senha_usuario, desbloquear_usuario, verificar_grupo, user_details
from config import *
from datetime import datetime, timedelta, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, AUTO_BIND_NO_TLS
from email_service import send_email

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessário para usar flash messages
load_dotenv()  # Carregar variáveis de ambiente do arquivo .env
logging.basicConfig(level=logging.DEBUG)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

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
    # send_email("teste", "allan.santos@amchambrasil.com.br","teste")
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

@app.route('/create_rh', methods=['GET'])
def get_create_rh():
    if 'username' in session:
        print(session['permissao'])
        if session['permissao'] == 'RH': 
            return render_template('create_rh.html')
        else:
            return redirect(url_for('rh'))
        
@app.route('/create_rh', methods=['POST'])
def post_create_rh():
    if 'username' in session and session['permissao'] == 'RH':
        employeeID = request.form.get('employeeID')
        nome = request.form.get('nome')
        sobrenome = request.form.get('sobrenome')
        data_nascimento = request.form.get('extensionAttribute1')
        data_contratacao = request.form.get('extensionAttribute2')
        departamento = request.form.get('department')
        cargo = request.form.get('cargo')
        telephoneNumber = request.form.get('telephoneNumber')
        regional = request.form.get('regional')
        physicalDeliveryOfficeName = request.form.get('physicalDeliveryOfficeName')
        st = request.form.get('st')
        company = request.form.get('company')
        
        query_params = f"?employeeID={employeeID}&nome={nome}&sobrenome={sobrenome}&data_nascimento={data_nascimento}&data_contratacao={data_contratacao}&departamento={departamento}&cargo={cargo}&telephoneNumber={telephoneNumber}&regional={regional}&physicalDeliveryOfficeName={physicalDeliveryOfficeName}&st={st}&company={company}"
        
        email_body = f"""
        <html>
            <body>
                <h2>Criar usuário</h2>
                <p><strong>Matrícula:</strong> {employeeID}</p>
                <p><strong>Nome:</strong> {nome}</p>
                <p><strong>Sobrenome:</strong> {sobrenome}</p>
                <p><strong>Data de Nascimento:</strong> {data_nascimento}</p>
                <p><strong>Data de Contratação:</strong> {data_contratacao}</p>
                <p><strong>Departamento:</strong> {departamento}</p>
                <p><strong>Cargo:</strong> {cargo}</p>
                <p><strong>Telefone:</strong> {telephoneNumber}</p>
                <p><strong>Regional:</strong> {regional}</p>
                <p><strong>Physical Delivery Office Name:</strong> {physicalDeliveryOfficeName}</p>
                <p><strong>State:</strong> {st}</p>
                <p><strong>Company:</strong> {company}</p>
                <a href="http://localhost:5000/complete_form{query_params}">
                    <button type="button">Complete Form</button>
                </a>
                
            </body>
        </html>
        """
        
        send_email("Criar usuário", "allan.santos@amchambrasil.com.br", email_body)

        return redirect(url_for('rh'))

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
    # page = request.args.get('page', 1, type=int)  # Número da página atual
    # per_page = 4  # Número de resultados por página
    
    if not query:
        flash("Por favor, forneça um nome de usuário para pesquisa.", 'error')
        return redirect(url_for('search_user'))
        
    # Conectar ao servidor AD
    server = Server(LDAP_SERVER, port=PORT_SSL, use_ssl=True, get_info=ALL)
    conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad, auto_bind=True)
    
    search_filter = f'(cn={query}*)'
    conn.search(base_dn, search_filter, attributes=['employeeID','cn', 'extensionAttribute1', 'extensionAttribute2', 'department', 'physicalDeliveryOfficeName', 
                                                    'title', 'telephoneNumber'])

    if conn.entries:
        users = conn.entries
        
        if(len(users)==1):
            user = users[0]
            user_info = {
                "employeeID": str(user.employeeID),
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
   
@app.route('/complete_form', methods=['GET', 'POST'])
def complete_form():
    if request.method == 'GET':
        # Obtendo os parâmetros da URL
        logging.debug('Requisição GET recebida com os seguintes parâmetros:')
        employeeID = request.form.get('employeeID')
        nome = request.form.get('nome')
        sobrenome = request.form.get('sobrenome')
        data_nascimento = request.form.get('data_nascimento')
        data_contratacao = request.form.get('data_contratacao')
        cargo = request.form.get('cargo')
        telephoneNumber = request.form.get('telephoneNumber')
        physicalDeliveryOfficeName = request.form.get('physicalDeliveryOfficeName')
        st = request.form.get('st')
        company = request.form.get('company')

        # Renderizando o formulário com os dados passados na URL
        return render_template('complete_form.html', 
                                employeeID=employeeID, 
                                nome=nome, 
                                sobrenome=sobrenome, 
                                data_nascimento=data_nascimento, 
                                data_contratacao=data_contratacao, 
                                cargo=cargo, 
                                telephoneNumber=telephoneNumber, 
                                physicalDeliveryOfficeName=physicalDeliveryOfficeName, 
                                st=st, 
                                company=company)
        
@app.route('/create_user', methods=['POST'])
def create_user():
    try:
        # Obtendo os valores do formulário com request.form.get() e fornecendo valores padrão vazios
        employeeID = request.form.get('employeeID', '').strip()
        nome = request.form.get('nome', '').strip()
        sobrenome = request.form.get('sobrenome', '').strip()
        logon = request.form.get('logon', '').strip()
        email = request.form.get('logon_email'),  # O e-mail já está incluído nos campos ocultos
        sAMAccountName = request.form.get('logon_sAMAccountName', '').strip()
        password = request.form.get('password', '').strip()
        regional = request.form.get('regional', '').strip()
        nascimento = request.form.get('data_nascimento', '').strip()
        contratacao = request.form.get('data_contratacao', '').strip()
        
        # Atributos adicionais
        physicalDeliveryOfficeName = request.form.get('physicalDeliveryOfficeName', '').strip()
        st = request.form.get('st', '').strip()
        company = request.form.get('company', '').strip()
        description = request.form.get('departamento', '').strip()
        title = request.form.get('cargo', '').strip()
        department = request.form.get('departamento', '').strip()
        
        print(f"Campos do formulário: {request.form}")

        # Validação dos campos
        if not all([nome, sobrenome, logon, sAMAccountName, email, password, regional]):
            flash('Por favor, preencha todos os campos.', 'error')
            return redirect(url_for('index'))

        print(f"Tentando conectar ao servidor AD: {LDAP_SERVER}:{PORT_SSL}")
        server = Server(LDAP_SERVER, port=PORT_SSL, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=True, authentication=SIMPLE, raise_exceptions=False)

        print("Conexão LDAP estabelecida com sucesso.")
    
        # Informações do novo usuário
        user_dn = f'CN={nome} {sobrenome},OU=Standard,OU=Users,OU={regional},DC=amchambr,DC=com,DC=br'
        user_attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'employeeID': employeeID,
            'cn': f'{nome} {sobrenome}',
            'sn': sobrenome,
            'givenName': nome,
            'sAMAccountName': sAMAccountName,
            'userPrincipalName': f'{logon}@amchambr.com.br',
            'displayName': f'{nome} {sobrenome}',
            'mail': email,
            'extensionAttribute1': nascimento,
            'extensionAttribute2': contratacao,
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
        
        # Remove atributos com valor None ou vazio
        user_attributes = {k: v for k, v in user_attributes.items() if v}

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