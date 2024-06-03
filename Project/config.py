import os
from dotenv import load_dotenv

load_dotenv()

LDAP_SERVER = os.getenv('LDAP_SERVER')
PORT_SSL = int(os.getenv('PORT_SSL'))
usuario_ad = os.getenv('USUARIO_AD')
senha_ad = os.getenv('SENHA_AD')
dominio_ad = os.getenv('DOMINIO_AD')
base_dn = os.getenv('BASE_DN')
SERVIDOR_AD = os.getenv('SERVIDOR_AD')
PORTA_AD = int(os.getenv('PORTA_AD'))
GRUPO_AD = os.getenv('grupo_dn')