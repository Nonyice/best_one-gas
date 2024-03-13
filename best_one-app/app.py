from flask import Flask, render_template, request, redirect, url_for, session

import psycopg2
import keyring

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'best_one'

#lets confgure the database 

db_host = "127.0.0.1"
db_name = "best_one"
db_user = "postgres"
db_password = keyring.get_password('best_one', 'postgres')

#lets create a route for homepage

@app.route('/')
def homepage():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

