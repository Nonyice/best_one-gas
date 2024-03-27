from flask import Flask, render_template, request, redirect, url_for, session, jsonify

from datetime import datetime

import psycopg2
import keyring
import bcrypt


app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'bestone'



# Database configuration
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

# Sample homepage route
@app.route('/')
def homepage():
    # Get the current date
    current_date = datetime.now().strftime('%A, %B %d, %Y') # Format for Day, Month Day, Year.
    return render_template('index.html', current_date = current_date)


# Admin section for login
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user information from the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, hashed_password, is_admin FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['id'] = user[0]
                session['username'] = user[1]
                session['is_admin'] = user[3]
                
                # Redirect based on admin status
                if session['is_admin']:
                    return redirect(url_for('admin_dashboard_2'))
                else:
                    return render_template('admin_login.html', message='You do not have admin privileges.')
            else:
                return render_template('admin_login.html', message='Invalid username or password')
        except psycopg2.Error as e:
            return render_template('error.html', message='Error logging in: {}'.format(e))
    
    return render_template('admin_login.html')





# Function to hash the password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Function to verify the password using bcrypt
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user information from the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, hashed_password, is_admin FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                session['id'] = user[0]
                session['username'] = user[1]
                session['is_admin'] = user[3]
                
                # Redirect based on admin status
                if session['is_admin']:
                    return redirect(url_for('admin_dashboard_2'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', message='Invalid username or password')
        except psycopg2.Error as e:
            print("Error:", e)
            return render_template('error.html', message='Error logging in: {}'.format(e))
    
    return render_template('login.html')



# Function to count the number of admin accounts
def count_admin_accounts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users WHERE is_admin = TRUE')
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        is_admin = False
    
        # Check if the admin checkbox is selected
        if 'admin_checkbox' in request.form:
            # Check if the number of admin accounts doesn't exceed 2
            if count_admin_accounts() < 1:
                is_admin = True
            else:
                return render_template('error.html', message='Cannot create more than 1 admin account')
    
        # Check if passwords match
        if password != confirm_password:
            return render_template('error.html', message='Passwords do not match')
    
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
        try:
            # Insert the user into the database with hashed password
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, hashed_password, is_admin) VALUES (%s, %s, %s)', (username, hashed_password.decode('utf-8'), is_admin))
            conn.commit()
            cursor.close()
            conn.close()
            return render_template('success.html')
        except psycopg2.Error as e:
            print("Error:", e)
            return render_template('error.html', message='Error creating user: {}'.format(e))

    return render_template('create_user.html')


# Route for removing a user
@app.route('/delete_user', methods=['GET', 'POST'])
def remove_user():
    if request.method == 'POST':
        username = request.form.get('username')  # Get the selected username from the form
        if username:
            try:
                conn = get_db_connection()  # Establish a connection to the database
                cursor = conn.cursor()
                # Execute SQL to delete the user with the selected username
                cursor.execute('DELETE FROM users WHERE username = %s', (username,))
                conn.commit()  # Commit the transaction
                cursor.close()
                conn.close()
                return render_template('success.html', message='User {} removed successfully'.format(username))
            except psycopg2.Error as e:
                error_message = 'Error removing user: {}'.format(e)
                return render_template('error.html', message=error_message)
        else:
            return render_template('error.html', message='No user selected for removal')
    else:
        # Fetch list of users from the database to populate the dropdown list
        users = get_users_from_database()
        return render_template('remove_user.html', users=users)

def get_users_from_database():
    try:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        )
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return users
    except psycopg2.Error as e:
        print("Error fetching users:", e)
        return []
    
    


def check_is_admin(username):
    conn = get_db_connection()  # Function to establish database connection
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE username = %s', (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return result[1]  # Assuming is_admin is a boolean column in the 'users' table
    else:
        return False
    

# Route for checking admin status
@app.route('/check_admin_status', methods=['POST'])
def check_admin_status():
    data = request.get_json()
    username = data.get('username')

    is_admin = check_is_admin(username)

    return jsonify({'is_admin': is_admin})





@app.route('/admin_dashboard')
def admin_dashboard_2():
    return render_template('admin_dashboard.html')


# Route for user dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Route for user logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('homepage'))



if __name__ == '__main__':
    app.run(debug=True)
