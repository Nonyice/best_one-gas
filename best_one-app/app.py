from flask import Flask, render_template, request, redirect, url_for, session

import psycopg2
import keyring
import bcrypt

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'best_one'

#lets confgure the database 

db_host = "127.0.0.1"
db_name = "best_one"
db_user = "postgres"
db_password = keyring.get_password('best_one', 'postgres')
db_port = '5432'





# Function to establish PostgreSQL connection
def get_db_connection():
    conn = psycopg2.connect(
        dbname=db_name,
        user=db_user,
        password=db_password,
        host=db_host,
        port=db_port
    )
    return conn

#lets create a route for homepage

@app.route('/')
def homepage():
    return render_template('index.html')


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Store username and hashed password in the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            print("Error:", e)
            return render_template('error.html', message='Error registering user')
    
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve hashed password from the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result:
                hashed_password = result[0]
                # Check if the provided password matches the hashed password
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    session['username'] = username
                    return redirect(url_for('dashboard'))
            
            return render_template('login.html', message='Invalid username or password')
        except psycopg2.Error as e:
            print("Error:", e)
            return render_template('error.html', message='Error logging in')
    
    return render_template('login.html')

# Route for user dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))




if __name__ == '__main__':
    app.run(debug=True)

