import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, to_email, body):
    msg = MIMEMultipart()
    msg['From'] = 'suporte.desktop@amchambrasil.com.br'
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))

    server = smtplib.SMTP(os.getenv('EMAIL_HOST'),os.getenv('EMAIL_PORT'))
    server.starttls()
    server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
    server.sendmail(os.getenv('EMAIL_USER'), to_email, msg.as_string())
    server.quit()