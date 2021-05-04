from application import  init_app

app = init_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8100, ssl_context=(app.config['CERTIFICATE_PATH'], app.config['SERVER_KEY']))
