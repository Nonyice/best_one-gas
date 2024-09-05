from flask import Flask, render_template, request, redirect, url_for, session, jsonify

import json
import datetime
from datetime import datetime



import psycopg2
from psycopg2 import errorcodes
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

# Homepage route
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

# Route for the admin dashboard
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



# Route to handle pump sales form submission
@app.route('/pump_sales', methods=['GET', 'POST'])
def pump_sales():
    if request.method == 'POST':
        # Get form data
        date_str = request.form['date']
        pump = request.form['pump']
        opening_reading = float(request.form['opening_reading'])
        closing_reading = float(request.form['closing_reading'])
        pump_attendant = request.form['pump_attendant']

        # Calculate pump sales in litres
        sales_litres = float(closing_reading - opening_reading)

        try:
            # Save pump sales data to the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO pump_sales (date, pump, opening_reading, closing_reading, pump_attendant, sales_litres) VALUES (%s, %s, %s, %s, %s, %s)',
                           (date_str, pump, opening_reading, closing_reading, pump_attendant, sales_litres))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            error_message = '{}'.format(e)
            return render_template('pump_error_message.html', error_message=str(e))

        # Fetch pump sales data from the database for the selected date
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT pump, SUM(closing_reading - opening_reading) AS sales_litres FROM pump_sales WHERE date = %s GROUP BY pump', (date_str,))
            pump_sales_data = dict(cursor.fetchall())
            cursor.close()
            conn.close()
        except Exception as e:
            return render_template('error.html', error_message=str(e))

        # Render the pump_sales.html template with pump sales data
        return render_template('pump_sales.html', pump_sales=pump_sales_data)
    else:
        # If it's a GET request, just render the pump_sales.html template without any data
        return render_template('pump_sales.html')





# Define the pump-tank assignment function
pump_tank_assignment = {
    'PMS Tank 1': ['PMS 4', 'PMS 5'],
    'PMS Tank 2': ['PMS 1', 'PMS 2', 'PMS 3'],
    'AGO Tank 1': ['AGO 1'],
    'AGO Tank 2': ['AGO 2']
}

def get_total_pump_sales_for_tank(pumps_for_selected_tank, date):
    # Construct the query to get the total pump sales for the given pumps and date
    query = 'SELECT SUM(sales_litres) FROM pump_sales WHERE pump IN %s AND date = %s'

    # Get the total pump sales for the given pumps and date
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (tuple(pumps_for_selected_tank), date))
    total_sales = cursor.fetchone()[0] or 0
    cursor.close()
    conn.close()

    return total_sales

# Flask route for calculating tank ullage
@app.route('/tanks', methods=['GET', 'POST'])
def tank_ullage():
    if request.method == 'POST':
        try:
            # Get form data
            date = request.form['date']
            tank = request.form['tank']
            opening_stock = int(request.form['opening_stock'])
            received_stock = int(request.form['received_stock'])
            closing_stock = int(request.form['closing_stock'])
            
            # Calculate depletion
            depletion = (opening_stock + received_stock) - closing_stock

            # Calculate sales_litres based on the selected tank
            selected_tank = request.form['tank']
            pumps_for_selected_tank = pump_tank_assignment.get(selected_tank, [])
            total_sales_litres = get_total_pump_sales_for_tank(pumps_for_selected_tank, date)

            # Calculate margin for the selected tank
            margin = {}
            margin[selected_tank] = total_sales_litres - depletion

            # Serialize margin to JSON
            margin_json = json.dumps(margin)

            # Save tank ullage data to the database
            conn = get_db_connection()
            cursor = conn.cursor()

            # Update the margin and total_sales_litres in the database
            cursor.execute('UPDATE underground SET total_sales_litres = %s, margin = %s WHERE date = %s AND tank = %s',
                           (total_sales_litres, margin_json, date, tank))
            conn.commit()

            cursor.execute('INSERT INTO underground (date, tank, opening_stock, received_stock, closing_stock, depletion, total_sales_litres, margin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                           (date, tank, opening_stock, received_stock, closing_stock, depletion, total_sales_litres, margin_json))
            conn.commit()

            cursor.close()
            conn.close()

            # Render template with tank ullage data
            return render_template('underground_tank.html', date=date, tank=tank, opening_stock=opening_stock,
                                   received_stock=received_stock, closing_stock=closing_stock,
                                   depletion=depletion, total_sales_litres=total_sales_litres, margin=margin)
        except psycopg2.Error as e:
            error_message = "Database error: {}".format(e)
            return render_template('tank_error_message.html', error_message=error_message)
        except Exception as e:
            error_message = "An error occurred: {}".format(e)
            return render_template('tank_error_message.html', error_message=error_message)
    else:
        # Render the tank ullage form for GET requests
        return render_template('underground_tank.html')






@app.route('/tank_ullage_display')
def tank_ullage_display():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM underground')
        tank_ullage_data = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('underground_display.html', tank_ullage_data=tank_ullage_data)
    
    except psycopg2.Error as e:
        # Handle PostgreSQL errors
        error_message = str(e)
        return render_template('error.html', error_message=error_message)
    
    except Exception as e:
        # Handle other exceptions
        error_message = str(e)
        return render_template('error.html', error_message=error_message)



if __name__ == '__main__':
    app.run(debug=True)
