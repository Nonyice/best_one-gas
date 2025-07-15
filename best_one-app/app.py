from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify

import datetime
from datetime import datetime, timedelta
from decimal import Decimal



import psycopg2 
from psycopg2 import sql, errors

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





@app.route('/pump_sales', methods=['GET', 'POST'])
def pump_sales():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch pumps and attendants from database for dropdowns
    cursor.execute('SELECT id, pump_name FROM pumps')
    pumps = cursor.fetchall()

    cursor.execute('SELECT id, attendant_name FROM attendants')
    attendants = cursor.fetchall()

    if request.method == 'POST':
        # Retrieve form data
        date_str = request.form['date']
        shift = request.form['shift']
        pump_id = int(request.form['pump_id'])
        attendant_name = request.form['attendant_name']
        closing_reading = Decimal(request.form['closing_reading'])
        rtt = Decimal(request.form['rtt'])

        # Determine opening reading based on shift
        if shift == 'morning':
            # Morning shift's opening is the previous day's afternoon closing
            cursor.execute('''
                SELECT closing_reading FROM pump_sales_afternoon 
                WHERE pump_id = %s AND date = %s
            ''', (pump_id, date_str))
            result = cursor.fetchone()
            
            if result and result[0] > 0:  # Valid afternoon closing reading exists
                opening_reading = result[0]
            else:
                # Fall back to the previous morning's closing if afternoon closing is zero or missing
                cursor.execute('''
                    SELECT closing_reading FROM pump_sales 
                    WHERE pump_id = %s AND date = (
                        SELECT MAX(date) FROM pump_sales 
                        WHERE pump_id = %s AND date < %s
                    )
                ''', (pump_id, pump_id, date_str))
                opening_reading = cursor.fetchone()[0] if cursor.rowcount > 0 else Decimal(0)

            target_table = 'pump_sales'  # Morning shift table

        else:  # Afternoon shift
            # Afternoon shift's opening is the current day's morning closing
            cursor.execute('''
                SELECT closing_reading FROM pump_sales 
                WHERE pump_id = %s AND date = %s
            ''', (pump_id, date_str))
            result = cursor.fetchone()
            
            if result:
                opening_reading = result[0]
            else:
                flash('Morning shift data is missing for the selected pump and date.', 'danger')
                return redirect(url_for('pump_sales'))

            target_table = 'pump_sales_afternoon'  # Afternoon shift table

        # Calculate sales litres and expected submission
        sales_litres = closing_reading - opening_reading - rtt
        cursor.execute('''
            SELECT p.product_type, pp.price FROM pumps p
            JOIN product_prices pp ON p.product_type = pp.product_type
            WHERE p.id = %s
        ''', (pump_id,))
        product_data = cursor.fetchone()
        if product_data:
            product_type, price = product_data
            expected_submission = sales_litres * Decimal(price)
        else:
            flash('Product type or price not found for this pump.', 'danger')
            return redirect(url_for('pump_sales'))

        # Insert into the target table (morning or afternoon)
        try:
            cursor.execute(f'''
                INSERT INTO {target_table} (date, shift, pump_id, opening_reading, closing_reading, 
                                            attendant_name, sales_litres, rtt, expected_submission)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (date_str, shift, pump_id, opening_reading, closing_reading, attendant_name, sales_litres, rtt, expected_submission))
            conn.commit()
            flash('Pump sales recorded successfully.', 'success')
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('This pump has already been recorded for the selected pump and shift.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'Failed to record pump sales. Error: {str(e)}', 'danger')
        finally:
            conn.close()

    return render_template('pump_sales.html', pumps=pumps, attendants=attendants)











# Assign pumps to tanks
@app.route('/assign_pumps', methods=['GET', 'POST'])
def assign_pumps():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch tank and pump data for the form
    cursor.execute('SELECT id, tank_name FROM tanks')
    tanks = cursor.fetchall()
    cursor.execute('SELECT id, pump_name FROM pumps')
    pumps = cursor.fetchall()

    if request.method == 'POST':
        tank_id = request.form['tank_id']
        pump_ids = request.form.getlist('pump_ids')  # Retrieve a list of selected pump IDs

        try:
            for pump_id in pump_ids:
                # Check if the pump is already assigned to another tank
                cursor.execute('SELECT * FROM pump_tank_assignment WHERE pump_id = %s', (pump_id,))
                if cursor.fetchone():
                    flash(f'Pump {pump_id} is already assigned to another tank.', 'danger')
                    continue

                # Insert pump-tank assignment if it's not already assigned
                cursor.execute('INSERT INTO pump_tank_assignment (tank_id, pump_id) VALUES (%s, %s)', (tank_id, pump_id))

            conn.commit()
            flash('Pump(s) assigned successfully', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Failed to assign pump(s) to tank: {str(e)}', 'danger')
        finally:
            conn.close()

        return redirect('/assign_pumps')

    # Render the form template
    return render_template('assign_pump.html', tanks=tanks, pumps=pumps)


@app.route('/pump_performance', methods=['GET', 'POST'])
def performance():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch tank names and IDs for the dropdown menu
    tanks_query = 'SELECT id, tank_name FROM tanks'
    cursor.execute(tanks_query)
    tanks = cursor.fetchall()

    performance_data = []
    tank_name = None

    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        tank_id = request.form['tank_id']

        # Get the name of the selected tank for display
        cursor.execute('SELECT tank_name FROM tanks WHERE id = %s', (tank_id,))
        tank_name = cursor.fetchone()[0] if cursor.rowcount > 0 else None

        # Retrieve all pumps associated with the selected tank
        cursor.execute('SELECT pump_id FROM pump_tank_assignment WHERE tank_id = %s', (tank_id,))
        pump_ids = [row[0] for row in cursor.fetchall()]

        if pump_ids:
            # Get total sales across both shifts for all associated pumps within the date range
            cursor.execute('''
                SELECT date, SUM(sales_litres) AS total_sales
                FROM (
                    SELECT date, sales_litres FROM pump_sales WHERE date BETWEEN %s AND %s AND pump_id = ANY(%s)
                    UNION ALL
                    SELECT date, sales_litres FROM pump_sales_afternoon WHERE date BETWEEN %s AND %s AND pump_id = ANY(%s)
                ) AS combined_sales
                GROUP BY date ORDER BY date
            ''', (start_date, end_date, pump_ids, start_date, end_date, pump_ids))

            sales_data = cursor.fetchall()

            for date, total_sales in sales_data:
                # Fetch opening, received, and closing stock for the tank on each date
                cursor.execute('''
                    SELECT opening_stock, received_stock, closing_stock
                    FROM underground
                    WHERE date = %s AND tank_id = %s
                ''', (date, tank_id))
                stock_data = cursor.fetchone()

                if stock_data:
                    opening_stock, received_stock, closing_stock = stock_data
                    # Calculate depletion
                    depletion = (opening_stock + received_stock - closing_stock) if (opening_stock + received_stock - closing_stock) > 0 else 0
                    # Calculate performance
                    performance = total_sales - depletion if depletion != 0 else 0
                else:
                    opening_stock = received_stock = closing_stock = depletion = performance = 0

                # Add all data for each date, including the tank name
                performance_data.append({
                    'date': date,
                    'tank_name': tank_name,
                    'total_sales': total_sales,
                    'opening_stock': opening_stock,
                    'received_stock': received_stock,
                    'closing_stock': closing_stock,
                    'depletion': depletion,
                    'performance': performance
                })

    conn.close()
    return render_template('pump_performance.html', tanks=tanks, performance_data=performance_data)







def get_previous_closing_stock(tank_id, date):
    
    query = '''
        SELECT closing_stock FROM underground WHERE tank_id = %s and date < %s ORDER BY date DESC LIMIT 1
    '''
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(query, (tank_id, date))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return result[0] if result else 0

@app.route('/underground_tanks', methods=['GET', 'POST'])
def tank_ullage():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch tank names for dropdown
    cursor.execute('SELECT id, tank_name FROM tanks')
    tanks = cursor.fetchall()

    if request.method == 'POST':
        try:
            # Get form data
            date = request.form['date']
            tank_id = request.form.get('tank_id')
            received_stock = float(request.form['received_stock'])
            closing_stock = float(request.form['closing_stock'])
            rate_per_litre = float(request.form.get('rate_per_litre', 0))
            vendor = request.form.get('vendor', '').strip()
            payments = float(request.form.get('payments', 0))
            outstanding_debts = float(request.form.get('outstanding_debts', 0))

            # Determine product type based on tank name
            cursor.execute('SELECT tank_name FROM tanks WHERE id = %s', (tank_id,))
            tank_name = cursor.fetchone()[0]
            
            if "PMS" in tank_name:
                product_type = "PMS"
            elif "AGO" in tank_name:
                product_type = "AGO"
            elif "DPK" in tank_name:
                product_type = "DPK"
            else:
                product_type = "UNKNOWN"

            # Calculate total value of received stock
            total_value = received_stock * rate_per_litre

            # Set opening stock based on previous closing stock
            opening_stock = get_previous_closing_stock(tank_id, date)

            # Insert into `underground` table
            cursor.execute('''
                INSERT INTO underground (date, tank_id, opening_stock, received_stock, closing_stock) 
                VALUES (%s, %s, %s, %s, %s)
            ''', (date, tank_id, opening_stock, received_stock, closing_stock))

            # Insert into `received_stock` table if received_stock > 0
            if received_stock >= 0:
                cursor.execute('''
                    INSERT INTO received_stock (date, product_type, tank_id, quantity, rate_per_litre, total_value, vendor, payments, outstanding_debts)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (date, product_type, tank_id, received_stock, rate_per_litre, total_value, vendor, payments, outstanding_debts))

            conn.commit()
            flash('Tank ullage recorded successfully', 'success')

        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('This tank has already been recorded for the selected date.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'Failed to record ullage. Error: {str(e)}', 'danger')
        finally:
            conn.close()
            return redirect(url_for('tank_ullage'))

    return render_template('underground_tank.html', tanks=tanks)






@app.route('/pump_sales_display')
def pump_sales_display():
    conn = get_db_connection()
    cursor = conn.cursor()


    cursor.execute('''SELECT date, pump_name, opening_reading, closing_reading, sales,
        expected_submission, rtt, attendant_name, shift
        FROM combined_pump_sales ORDER BY date DESC''')
    sales_data = cursor.fetchall()

    conn.close()    
    return render_template('pump_sales_display.html', sales_data=sales_data) 
    


@app.route('/tank_ullage_display')
def tank_ullage_display():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''SELECT u.date, t.tank_name, u.opening_stock, u.received_stock, u.closing_stock FROM underground u
        JOIN tanks t ON u.tank_id = t.id ORDER BY u.date DESC''')
        tank_ullage_data = cursor.fetchall()
    
        return render_template('underground_display.html', tank_ullage_data=tank_ullage_data)
    except psycopg2.errors as e:
        conn.rollback()
        flash(f'Something went wrong:', {str(e)})
    
    except Exception as e:
        error_message = "An error occurred: {}".format(e)
        return render_template('tank_error_message.html', error_message=error_message)
    finally:
        cursor.close()
        conn.close()
        return render_template('underground_display.html', tank_ullage_data=tank_ullage_data)

    

    



@app.route('/create_attendants', methods=['GET', 'POST'])
def create_attendants():
    if request.method == 'POST':
        attendant_name = request.form.get('attendant_name')
        monthly_pay = request.form.get('monthly_pay')

        if not attendant_name or not monthly_pay:
            flash("Both fields are required.", "danger")
            return render_template('create_attendant.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert into attendants table
            cursor.execute('INSERT INTO attendants (attendant_name, monthly_pay) VALUES (%s, %s)',
            (attendant_name, float(monthly_pay)))

            conn.commit()
            cursor.close()
            conn.close()

            flash('Attendant created successfully', "success")
            return redirect(url_for('create_attendants'))

        except psycopg2.errors.UniqueViolation:
            flash("Attendant's name already exists, Try again please", "danger")
            return render_template('create_attendant.html')
        
        except psycopg2.Error as e:
            print("Database error:", e.pgcode, e.pgerror)
            flash("An error occurred. Please try again: {e.pgerror}", "danger")
            return render_template('create_attendants.html')
        except Exception as e:
            print("General error:", str(e))
            flash("An unexpected error occured: {str(e)}", "danger")
            return render_template('create_pumps.html')

    return render_template('create_attendant.html')


@app.route('/create_pumps', methods=['GET', 'POST'])
def create_pumps():
    if request.method == 'POST':
        pump_name = request.form.get('pump_name')
        product_type = request.form.get('product_type')
        if not pump_name or not product_type:
            flash("Pump name and product type are required.", "danger")
            return render_template('create_pumps.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert into pumps table
            cursor.execute('INSERT INTO pumps (pump_name, product_type) VALUES (%s, %s)', (pump_name, product_type))

            conn.commit()
            cursor.close()
            conn.close()

            flash('Pump created successfully', "success")
            return redirect(url_for('create_pumps'))

        except psycopg2.errors.UniqueViolation:
            flash("Pump already exists, Try again please", "danger")
            return render_template('create_pumps.html')
        
        except psycopg2.Error as e:
            print("Dtabase error:", e.pgcode, e.pgerror)
            flash("An error occurred. Please try again: {e.pgerror}", "danger")
            return render_template('create_pumps.html')
        except Exception as e:
            print("General error:", str(e))
            flash("An unexpected error occured: {str(e)}", "danger")
            return render_template('create_pumps.html')
        

    return render_template('create_pumps.html')



@app.route('/product_prices', methods=['GET', 'POST'])
def product_prices():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT product_type FROM pumps")
    product_types = cursor.fetchall()

    if request.method == 'POST':
        # Get form data
        product_type = request.form.get('product_type')
        price = request.form.get('price')

        # Update or insert price
        cursor.execute('''
            INSERT INTO product_prices (product_type, price, date)
            VALUES (%s, %s, NOW())
            ON CONFLICT (product_type)
            DO UPDATE SET price = EXCLUDED.price, date = NOW()
        ''', (product_type, price))
        conn.commit()
        flash('Product price updated successfully!', 'success')

    # Fetch all prices for display
    cursor.execute('SELECT product_type, price, date FROM product_prices ORDER BY product_type')
    prices = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('prices.html', prices=prices, product_types=product_types)






#Logic to get expected submission
def calculate_expected_submission(attendant_name, date):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve assigned pumps for the attendant
    cursor.execute('''
        SELECT p.name, p.product_type 
        FROM attendant_pump_assignment apa
        JOIN pumps p ON apa.pump_name = p.name
        WHERE apa.attendant_name = %s
    ''', (attendant_name,))
    pumps = cursor.fetchall()

    day_sales = 0
    for pump_name, product_type in pumps:
        # Fetch sales litres for each pump on the specified date
        cursor.execute('''
            SELECT (sales_litres)
            FROM pump_sales 
            WHERE pump_name = %s AND date = %s
        ''', (pump_name, date))
        sales_in_litres = cursor.fetchone()[0]

        # Retrieve the latest price for the product type
        cursor.execute('''
            SELECT price 
            FROM product_prices 
            WHERE product_name = %s 
            ORDER BY date DESC 
            LIMIT 1
        ''', (product_type,))
        price = cursor.fetchone()[0] or 0

        day_sales += sales_in_litres * price

    conn.close()
    return day_sales


@app.route('/submit_money', methods=['GET', 'POST'])
def submit_money():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch attendants and pumps for dropdowns
    cursor.execute('SELECT attendant_name, monthly_pay FROM attendants')
    attendants = cursor.fetchall()
    cursor.execute('SELECT id, pump_name FROM pumps')
    pumps = cursor.fetchall()

    if request.method == 'POST':
        try:
            # Retrieve form data
            attendant_name = request.form['attendant_name']
            pump_id = request.form['pump_id']
            date = request.form['date']
            cash = Decimal(request.form.get('cash', '0') or '0.00')
            pos1 = Decimal(request.form.get('pos1', '0') or '0.00')
            pos2 = Decimal(request.form.get('pos2', '0') or '0.00')
            transfers = Decimal(request.form.get('transfers', '0.00') or '0.00')
            customer_credits = Decimal(request.form.get('customer_credits', '0') or '0.00')

            # Calculate total submission
            total_submission = cash + pos1 + pos2 + transfers + customer_credits

            # Retrieve total sales amount for the selected pump from morning and afternoon shifts
            cursor.execute('''
                SELECT 
                    COALESCE(SUM(morning_sales.sales_litres * pp.price), 0) AS morning_sales_amount,
                    COALESCE(SUM(afternoon_sales.sales_litres * pp.price), 0) AS afternoon_sales_amount
                FROM product_prices pp
                LEFT JOIN (
                    SELECT ps.sales_litres, p.product_type
                    FROM pump_sales ps
                    JOIN pumps p ON ps.pump_id = p.id
                    WHERE ps.date = %s AND ps.attendant_name = %s AND ps.pump_id = %s
                ) AS morning_sales ON morning_sales.product_type = pp.product_type
                LEFT JOIN (
                    SELECT psa.sales_litres, p2.product_type
                    FROM pump_sales_afternoon psa
                    JOIN pumps p2 ON psa.pump_id = p2.id
                    WHERE psa.date = %s AND psa.attendant_name = %s AND psa.pump_id = %s
                ) AS afternoon_sales ON afternoon_sales.product_type = pp.product_type
            ''', (date, attendant_name, pump_id, date, attendant_name, pump_id))

            # Fetch the results and calculate total sales amount
            result = cursor.fetchone()
            morning_sales_amount = result[0] or Decimal(0)
            afternoon_sales_amount = result[1] or Decimal(0)
            total_sales_amount = morning_sales_amount + afternoon_sales_amount

            # Calculate submission difference
            submission_difference = total_sales_amount - total_submission

            # Update attendant's monthly pay based on submission difference
            if submission_difference > 0:
                cursor.execute('UPDATE attendants SET monthly_pay = monthly_pay - %s WHERE attendant_name = %s', (submission_difference, attendant_name))
            else:
                cursor.execute('UPDATE attendants SET monthly_pay = monthly_pay + %s WHERE attendant_name = %s', (abs(submission_difference), attendant_name))

            # Insert submission record
            cursor.execute('''
                INSERT INTO money_submissions (date, attendant_name, pump_id, cash, pos1, pos2, transfers, customer_credits, total_submission, total_sales_amount, submission_difference)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (date, attendant_name, pump_id, cash, pos1, pos2, transfers, customer_credits, total_submission, total_sales_amount, submission_difference))

            # Save pos details

            cursor.execute("""INSERT INTO pos (date, attendant_name, pos1, pos2) VALUES (%s, %s, %s, %s)
            """, (date, attendant_name, pos1, pos2)) 
            
            conn.commit()
            flash('Submission recorded successfully and monthly pay updated.', 'success')
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('This account has already been recorded for the selected pump.', 'danger')
        except Exception as e:
            conn.rollback()
            flash(f'Failed to record submission. Error: {str(e)}', 'danger')
        finally:
            conn.close()
            return redirect(url_for('submit_money'))

    return render_template('submissions.html', attendants=attendants, pumps=pumps)




@app.route('/submission_display')
def get_submission_records():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query to fetch submission records, treating morning and afternoon shifts independently
    cursor.execute('''
        SELECT ms.date, ms.attendant_name, p.pump_name,
        morning_sales.total_sales_litres AS morning_sales_litres,
        afternoon_sales.total_sales_litres AS afternoon_sales_litres,
        morning_sales.total_sales_amount AS morning_sales_amount,
        afternoon_sales.total_sales_amount AS afternoon_sales_amount,
        pp.price AS product_price,
        ms.total_submission,
        ms.customer_credits,
        ms.total_submission - ms.customer_credits AS actual_submission,
        ms.submission_difference,
        a.monthly_pay AS updated_monthly_pay
        FROM money_submissions ms
        JOIN attendants a ON ms.attendant_name = a.attendant_name

        -- Separate morning sales from pump_sales table
        LEFT JOIN (
            SELECT ps.attendant_name, ps.date, ps.pump_id, 
            SUM(ps.sales_litres) AS total_sales_litres,
            SUM(ps.sales_litres * pp.price) AS total_sales_amount
            FROM pump_sales ps
            JOIN pumps p ON ps.pump_id = p.id
            JOIN product_prices pp ON p.product_type = pp.product_type
            GROUP BY ps.attendant_name, ps.date, ps.pump_id
        ) AS morning_sales ON morning_sales.attendant_name = ms.attendant_name 
                            AND morning_sales.date = ms.date 
                            AND morning_sales.pump_id = ms.pump_id

        -- Separate afternoon sales from pump_sales_afternoon table
        LEFT JOIN (
            SELECT psa.attendant_name, psa.date, psa.pump_id, 
            SUM(psa.sales_litres) AS total_sales_litres,
            SUM(psa.sales_litres * pp.price) AS total_sales_amount
            FROM pump_sales_afternoon psa
            JOIN pumps p2 ON psa.pump_id = p2.id
            JOIN product_prices pp ON p2.product_type = pp.product_type
            GROUP BY psa.attendant_name, psa.date, psa.pump_id
        ) AS afternoon_sales ON afternoon_sales.attendant_name = ms.attendant_name 
        AND afternoon_sales.date = ms.date 
        AND afternoon_sales.pump_id = ms.pump_id

        -- Pump and product price information
        JOIN pumps p ON morning_sales.pump_id = p.id OR afternoon_sales.pump_id = p.id
        JOIN product_prices pp ON p.product_type = pp.product_type

        ORDER BY ms.date DESC
    ''')

    submissions = [
        {
            'date': row[0],
            'attendant_name': row[1],
            'pump': row[2],
            'morning_sales_litres': row[3],
            'afternoon_sales_litres': row[4],
            'morning_sales_amount': row[5],
            'afternoon_sales_amount': row[6],
            'product_price': row[7],
            'total_submission': row[8],
            'customer_credits': row[9],
            'actual_submission': row[10],
            'submission_difference': row[11],
            'updated_monthly_pay': row[12]
        }
        for row in cursor.fetchall()
    ]

    conn.close()
    return render_template('submissions_display.html', submissions=submissions)






@app.route('/pos_display')
def pos_display():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Fetch start and end dates from request args, if provided
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
    
        query = """
        SELECT date, attendant_name, pos1, pos2
        FROM pos ORDER BY date DESC
    """
    
        if start_date and end_date:
            try:
                cursor.execute("""SELECT date, attendant_name, pos1, pos2
                FROM pos
                WHERE date BETWEEN %s AND %s;""", (start_date, end_date))
            except Exception as e:
                flash(f"Error: {str(e)}", 'danger')
        else:
            cursor.execute(query)
    
        logs = cursor.fetchall()

        #Total pos
        total_pos = sum(log[2] + log[3] for log in logs)
        
        cursor.close()
        conn.close()
        return render_template('pos_log.html', logs=logs, total_pos=total_pos)
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")

    return render_template('admin_dashboard.html', logs=logs, total_pos=total_pos)








@app.route('/create_tank', methods=['GET', 'POST'])
def create_tank():
    if request.method == 'POST':
        tank_name = request.form['tank_name']
        capacity = request.form.get('capacity', type=float, default=0.00)
        desk_stock = request.form.get('desk_stock', type=float, default=0.00)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO tanks (tank_name, capacity, desk_stock) VALUES (%s, %s, %s)', (tank_name, capacity, desk_stock))

            conn.commit()
            flash('Tank created successfully', 'success')
        except errors.UniqueViolation:
            conn.rollback()
            flash('Tank name already exist. Please chose a different name.', 'danger')

        except Exception as e:
            conn.rollback()
            flash('Failed to create tank {}'.format(str(e)), 'danger')
        finally:
            conn.close()

        return redirect('/create_tank')
    return render_template('create_tanks.html')




# Function to add a new customer with initial credit amount
def add_customer(customer_name, credit_amount=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Determine initial status and remark based on credit amount
        status = "Outstanding" if credit_amount > 0 else "Cleared"
        remark = f"Outstanding {credit_amount}" if credit_amount > 0 else "Cleared completely"
        
        cursor.execute("""
            INSERT INTO customer_credit (customer_name, credit_amount, debit_amount, status, remark)
            VALUES (%s, %s, %s, %s, %s);
        """, (customer_name, credit_amount, 0, status, remark))
        
        # Insert into customer_credit_log
        cursor.execute("""
            INSERT INTO customer_credit_log (customer_name, credit_amount, debit_amount, status, remark)
            VALUES (%s, %s, %s, %s, %s);
        """, (customer_name, credit_amount, 0, status, remark))
        
        conn.commit()
    except Exception as e:
        print("Error adding customer:", e)
    finally:
        cursor.close()
        conn.close()

# Function to update credit for a customer
def update_credit(customer_name, credit_increase=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Update credit amount for the customer
        cursor.execute("""
            UPDATE customer_credit
            SET credit_amount = credit_amount + %s
            WHERE customer_name = %s;
        """, (credit_increase, customer_name))
        
        # Retrieve updated credit and debit amounts
        cursor.execute("""
            SELECT credit_amount, debit_amount FROM customer_credit
            WHERE customer_name = %s;
        """, (customer_name,))
        credit, debit = cursor.fetchone()
        
        # Determine the status and remark based on credit and debit values
        status = "Outstanding" if credit > debit else "Cleared"
        remark = f"Outstanding {credit - debit}" if credit > debit else "Cleared completely"
        
        # Update status and remark fields in the customer_credit table
        cursor.execute("""
            UPDATE customer_credit
            SET status = %s, remark = %s
            WHERE customer_name = %s;
        """, (status, remark, customer_name))
        
        # Insert transaction into customer_credit_log
        cursor.execute("""
            INSERT INTO customer_credit_log (customer_name, credit_amount, debit_amount, status, remark)
            VALUES (%s, %s, %s, %s, %s);
        """, (customer_name, credit_increase, 0, status, remark))
        
        conn.commit()
    except Exception as e:
        print("Error updating credit:", e)
    finally:
        cursor.close()
        conn.close()

# Function to update debit for a customer
def update_debit(customer_name, debit_increase=0):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Update debit amount for the customer
        cursor.execute("""
            UPDATE customer_credit
            SET debit_amount = debit_amount + %s
            WHERE customer_name = %s;
        """, (debit_increase, customer_name))
        
        # Retrieve updated credit and debit amounts
        cursor.execute("""
            SELECT credit_amount, debit_amount FROM customer_credit
            WHERE customer_name = %s;
        """, (customer_name,))
        credit, debit = cursor.fetchone()
        
        # Determine the status and remark based on credit and debit values
        status = "Outstanding" if credit > debit else "Cleared"
        remark = f"Outstanding {credit - debit}" if credit > debit else "Cleared completely"
        
        # Update status and remark fields in the customer_credit table
        cursor.execute("""
            UPDATE customer_credit
            SET status = %s, remark = %s
            WHERE customer_name = %s;
        """, (status, remark, customer_name))
        
        # Insert transaction into customer_credit_log
        cursor.execute("""
            INSERT INTO customer_credit_log (customer_name, credit_amount, debit_amount, status, remark)
            VALUES (%s, %s, %s, %s, %s);
        """, (customer_name, 0, debit_increase, status, remark))
        
        conn.commit()
    except Exception as e:
        print("Error updating debit:", e)
    finally:
        cursor.close()
        conn.close()







@app.route('/customer_credit')
def customer_credit():
    customers = get_all_customers()
    return render_template("customer_credit.html", customers=customers)

@app.route('/add_customer', methods=['POST'])
def add_customer_route():
    customer_name = request.form['name']
    credit_amount = float(request.form['credit_amount'])
    add_customer(customer_name, credit_amount)
    return redirect(url_for('customer_credit'))


@app.route('/update_credit', methods=['POST'])
def update_credit_route():
    customer_name = request.form['customer_name']
    credit_increase = float(request.form['credit_increase'])
    update_credit(customer_name, credit_increase)
    return redirect(url_for('customer_credit'))

@app.route('/update_debit', methods=['POST'])
def update_debit_route():
    customer_name = request.form['customer_name']
    debit_increase = float(request.form['debit_increase'])
    update_debit(customer_name, debit_increase)
    return redirect(url_for('customer_credit'))

def get_all_customers():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM customer_credit")
    customers = cur.fetchall()
    cur.close()
    conn.close()
    return customers




def view_customer_status(customer_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT customer_name, credit_amount, debit_amount, status, remark
        FROM customer_credit
        WHERE id = %s
    """, (customer_id,))
    customer_data = cursor.fetchone()
    cursor.close()
    conn.close()
    return customer_data






#Clear Database table entries

@app.route('/clear_table', methods=['GET', 'POST'])
def clear_table():
    if request.method == 'POST':
        table_name = request.form['table_name']

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Clear all entries from the specified table
            query = sql.SQL("DELETE FROM {}").format(sql.Identifier(table_name))
            cursor.execute(query)
            conn.commit()
            
            flash(f"All entries from '{table_name}' have been deleted successfully.", "success")
        except psycopg2.Error as e:
            conn.rollback()
            flash(f"Error: {str(e)}", "danger")
        finally:
            if conn:
                cursor.close()
                conn.close()
        
        return redirect(url_for('clear_table'))
    
    return render_template('clear_table.html')



@app.route('/add_item', methods=['GET', 'POST'])
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        unit_price = Decimal(request.form['unit_price'])
        quantity = int(request.form['quantity'])
        low_stock_alert = int(request.form['low_stock_alert'])

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check if an item with the same name exists
            cursor.execute('SELECT id, quantity FROM stock_items WHERE item = %s', (name,))
            existing_item = cursor.fetchone()

            if existing_item:
                # If the item exists, update its quantity and last_updated timestamp
                item_id, current_quantity = existing_item
                new_quantity = current_quantity + quantity
                cursor.execute('''
                    UPDATE stock_items 
                    SET quantity = %s, unit_price = %s, low_stock_alert = %s, last_updated = %s 
                    WHERE id = %s
                ''', (new_quantity, unit_price, low_stock_alert, datetime.now(), item_id))
                flash(f"Item '{name}' updated with additional {quantity} units.", 'success')
            else:
                # If the item does not exist, insert it as a new row
                cursor.execute('''
                    INSERT INTO stock_items (item, category, unit_price, quantity, low_stock_alert, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (name, category, unit_price, quantity, low_stock_alert, datetime.now()))
                flash(f"Item '{name}' added to stock!", 'success')

            conn.commit()

        except Exception as e:
            conn.rollback()
            flash(f"An error occurred: {str(e)}", 'danger')

        finally:
            conn.close()

        return redirect(url_for('view_inventory'))

    return render_template('add_bar_items.html')






# Route to view inventory and check for low stock
@app.route('/inventory')
def view_inventory():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stock_items ORDER BY last_updated DESC')
    items = cursor.fetchall()

    # Check for low stock and flash alerts
    for item in items:
        if item[4] <= item[5]:  # Check quantity against low_stock_alert
            flash(f"Low stock alert for {item[1]}!", 'warning')

    conn.close()
    return render_template('bar_inventory.html', items=items)




# Route to handle sales transaction and update stock
@app.route('/sell_item', methods=['GET', 'POST'])
def sell_item():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch available items for dropdown
    cursor.execute('SELECT id, item, quantity FROM stock_items')
    items = cursor.fetchall()

    if request.method == 'POST':
        item_id = int(request.form['item_id'])
        quantity_sold = int(request.form['quantity'])

        # Retrieve item price and current stock
        cursor.execute('SELECT unit_price, quantity FROM stock_items WHERE id = %s', (item_id,))
        item = cursor.fetchone()
        unit_price = item[0]
        current_quantity = item[1]

        if quantity_sold > current_quantity:
            if current_quantity == 0:

                flash(f'Cannot sell {quantity_sold} units! Stock for this item is currently exhasted', 'danger')
            else:
                flash(f"Cannot sell {quantity_sold} units at the moment, availabe in stock! is {current_quantity}", 'danger')
            conn.close()
            return redirect(url_for('sell_item'))

        # Update quantity in stock
        new_quantity = current_quantity - quantity_sold
        cursor.execute('UPDATE stock_items SET quantity = %s WHERE id = %s', (new_quantity, item_id))

        # Insert sale transaction
        total_price = unit_price * quantity_sold
        cursor.execute('''
            INSERT INTO bar_sales (item_id, quantity, total_price, timestamp)
            VALUES (%s, %s, %s, %s)
        ''', (item_id, quantity_sold, total_price, datetime.now()))

        conn.commit()
        conn.close()

        flash(f'Sale recorded successfully! Total: N{total_price}', 'success')
        return redirect(url_for('view_inventory'))

    conn.close()
    return render_template('sell_item.html', items=items)



@app.route('/sales_log')
def sales_log():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch sales transactions
    cursor.execute('''
        SELECT bs.id, si.item, bs.quantity, bs.total_price, bs.timestamp
        FROM bar_sales bs
        JOIN stock_items si ON bs.item_id = si.id
        ORDER BY bs.timestamp DESC
    ''')
    sales = cursor.fetchall()

    conn.close()
    return render_template('sales_log.html', sales=sales)



@app.route('/add_md_transaction', methods=['GET', 'POST'])
def add_md_transaction():
    if request.method == 'POST':
        transaction_type = request.form['transaction_type']
        amount = Decimal(request.form['amount'])
        purpose = request.form['purpose']

        if transaction_type not in ['credit', 'debit']:
            flash('Invalid transaction type!', 'danger')
            return redirect(url_for('add_md_transaction'))

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert the transaction into the database
        cursor.execute('''
            INSERT INTO md_transactions (transaction_type, amount, purpose, transaction_date)
            VALUES (%s, %s, %s, %s)
        ''', (transaction_type, amount, purpose, datetime.now()))
        conn.commit()
        conn.close()

        flash(f'MD {transaction_type} transaction recorded successfully!', 'success')
        return redirect(url_for('view_md_transactions'))

    return render_template('add_md_transactions.html')



@app.route('/view_md_transactions', methods=['GET', 'POST'])
def view_md_transactions():
    conn = get_db_connection()
    cursor = conn.cursor()

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = '''
        SELECT transaction_type, amount, purpose, created_at
        FROM md_transactions
    '''
    params = []

    if start_date and end_date:
        # Extend the end_date to include the full day range
        end_date = f"{end_date} 23:59:59"
        query += ' WHERE created_at BETWEEN %s AND %s'
        params = [start_date, end_date]
        flash(f'Showing transactions from {start_date} to {end_date.split()[0]}', 'info')

    query += ' ORDER BY created_at DESC'
    cursor.execute(query, params)
    transactions = cursor.fetchall()

    def format_money(amount):
        return "{:,.2f}".format(amount)

    conn.close()
    return render_template('view_md_transactions.html', transactions=transactions)



@app.route('/expenses', methods=['GET', 'POST'])
def add_expense():
    if request.method == 'POST':
        date = request.form['date']
        description = request.form['description']
        category = request.form['category']
        amount = Decimal(request.form['amount'])
        recorded_by = request.form['recorded_by']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO expenses (date, description, category, amount, recorded_by)
            VALUES (%s, %s, %s, %s, %s)
        ''', (date, description, category, amount, recorded_by))
        conn.commit()
        conn.close()

        flash('Expense added successfully!', 'success')
        return redirect(url_for('add_expense'))

    return render_template('expenses.html')

@app.route('/add_deposit', methods=['GET', 'POST'])
def add_deposit():
    if request.method == 'POST':
        date = request.form['date']
        amount = Decimal(request.form['amount'])
        source = request.form['source']
        recorded_by = request.form['recorded_by']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO deposits (date, amount, source, recorded_by)
            VALUES (%s, %s, %s, %s)
        ''', (date, amount, source, recorded_by))
        conn.commit()
        conn.close()

        flash('Deposit added successfully!', 'success')
        return redirect(url_for('add_deposit'))

    return render_template('add_deposit.html')






@app.route('/view_expenses', methods=['GET', 'POST'])
def view_expenses():
    conn = get_db_connection()
    cursor = conn.cursor()

    expenses = []
    deposits = []
    total_expenses = 0
    total_deposits = 0

    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Fetch expenses
        cursor.execute('''
            SELECT date, description, category, amount, recorded_by
            FROM expenses
            WHERE date BETWEEN %s AND %s
            ORDER BY date 
        ''', (start_date, end_date))
        expenses = cursor.fetchall()

        # Fetch deposits
        cursor.execute('''
            SELECT date, source, amount, recorded_by
            FROM deposits
            WHERE date BETWEEN %s AND %s
            ORDER BY date DESC
        ''', (start_date, end_date))
        deposits = cursor.fetchall()

        # Calculate totals
        total_expenses = sum([expense[3] for expense in expenses])
        total_deposits = sum([deposit[2] for deposit in deposits])

    conn.close()

    return render_template(
        'view_expenses.html',
        expenses=expenses,
        deposits=deposits,
        total_expenses=total_expenses,
        total_deposits=total_deposits
    )


@app.route('/reports', methods=['GET', 'POST'])
def reports():
    data = None
    start_date = None
    end_date = None

    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        # Validate date range
        if not start_date or not end_date or start_date > end_date:
            flash('Invalid date range. Please check your inputs.', 'error')
            return redirect(request.url)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Stock Report
        cursor.execute('''
            SELECT item, category, unit_price, SUM(quantity) AS total_quantity,
                   SUM(quantity * unit_price) AS total_value
            FROM stock_items
            WHERE last_updated BETWEEN %s AND %s
            GROUP BY item, category, unit_price
            ORDER BY total_quantity DESC
        ''', (start_date, end_date))
        stock_report = cursor.fetchall()

        # Pump Sales Report
        cursor.execute('''  
            SELECT p.pump_name, 
            SUM(ps.sales_litres) + SUM(psa.sales_litres) AS total_sales_litres,
            SUM((ps.sales_litres + psa.sales_litres) * pp.price) AS total_sales_amount
            FROM pump_sales ps
            LEFT JOIN pump_sales_afternoon psa ON ps.pump_id = psa.pump_id AND ps.date = psa.date
            JOIN pumps p ON ps.pump_id = p.id
            JOIN product_prices pp ON p.product_type = pp.product_type
            WHERE ps.date BETWEEN %s AND %s
            GROUP BY p.pump_name
            ORDER BY total_sales_litres DESC
        ''', (start_date, end_date))
        pump_sales_report = cursor.fetchall()

        # Pump Performance Report
        cursor.execute('''  
            SELECT u.tank_id, t.tank_name, 
            SUM(ps.sales_litres + psa.sales_litres) AS total_sales,
            SUM(u.opening_stock + u.received_stock - u.closing_stock) AS depletion,
            SUM(ps.sales_litres + psa.sales_litres) - SUM(u.opening_stock + u.received_stock - u.closing_stock) AS performance
            FROM underground u
            LEFT JOIN pumps p ON u.tank_id = u.tank_id
            LEFT JOIN pump_sales ps ON p.id = ps.pump_id
            LEFT JOIN pump_sales_afternoon psa ON p.id = psa.pump_id AND ps.date = psa.date
            JOIN tanks t ON u.tank_id = t.id
            WHERE ps.date BETWEEN %s AND %s
            GROUP BY u.tank_id, t.tank_name
            ORDER BY performance DESC
        ''', (start_date, end_date))
        pump_performance_report = cursor.fetchall()

        # Received Stock Summary
        cursor.execute('''
            SELECT r.product_type, t.tank_name, 
            SUM(r.quantity) AS total_received_quantity,
            SUM(r.quantity * r.rate_per_litre) AS total_received_value
            FROM received_stock r
            JOIN tanks t ON r.tank_id = t.id
            WHERE r.date BETWEEN %s AND %s
            GROUP BY r.product_type, t.tank_name
            ORDER BY total_received_value DESC
        ''', (start_date, end_date))
        received_stock_summary = cursor.fetchall()

        # Profit Margin Calculation
        cursor.execute('''
            SELECT r.product_type, 
                   SUM(r.quantity * r.rate_per_litre) AS total_received_value,
                   SUM((ps.sales_litres + psa.sales_litres) * pp.price) AS total_sales_value,
                   SUM((ps.sales_litres + psa.sales_litres) * pp.price) - SUM(r.quantity * r.rate_per_litre) AS profit_margin
            FROM received_stock r
            JOIN tanks t ON r.tank_id = t.id
            JOIN pumps p ON t.id = r.tank_id
            JOIN pump_sales ps ON p.id = ps.pump_id
            LEFT JOIN pump_sales_afternoon psa ON ps.pump_id = psa.pump_id AND ps.date = psa.date
            JOIN product_prices pp ON p.product_type = pp.product_type
            WHERE r.date BETWEEN %s AND %s
            GROUP BY r.product_type
            ORDER BY profit_margin DESC
        ''', (start_date, end_date))
        profit_margin_summary = cursor.fetchall()

        # Financial Transactions
        cursor.execute('''
            SELECT SUM(amount) AS total_deposits
            FROM deposits
            WHERE date BETWEEN %s AND %s
        ''', (start_date, end_date))
        total_deposits = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT SUM(amount) AS total_expenses
            FROM expenses
            WHERE date BETWEEN %s AND %s
        ''', (start_date, end_date))
        total_expenses = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT SUM(amount) AS md_contributions
            FROM md_transactions
            WHERE transaction_type = 'credit' AND created_at BETWEEN %s AND %s
        ''', (start_date, end_date))
        md_contributions = cursor.fetchone()[0] or 0

        cursor.execute('''
            SELECT SUM(amount) AS md_withdrawals
            FROM md_transactions
            WHERE transaction_type = 'debit' AND created_at BETWEEN %s AND %s
        ''', (start_date, end_date))
        md_withdrawals = cursor.fetchone()[0] or 0

        conn.close()

        data = {
            'stock_report': stock_report,
            'pump_sales_report': pump_sales_report,
            'pump_performance_report': pump_performance_report,
            'received_stock_summary': received_stock_summary,
            'profit_margin_summary': profit_margin_summary,
            'total_deposits': total_deposits,
            'total_expenses': total_expenses,
            'md_contributions': md_contributions,
            'md_withdrawals': md_withdrawals,
            'net_balance': total_deposits - total_expenses + md_contributions - md_withdrawals,
        }

    return render_template('reports.html', data=data, start_date=start_date, end_date=end_date)

@app.route('/revenue')
def revenue():
    return render_template('revenue.html')


@app.route('/bar')
def bar():
    return render_template('bar.html')






@app.route('/business_position', methods=['GET'])
def business_position():
    try:
        # Get the date range from the request (start_date and end_date)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total value of received stock with quantity and rate_per_litre
        cursor.execute(''' 
            SELECT date, product_type, vendor, quantity, rate_per_litre, 
            SUM(total_value) AS total_received_stock_value,
            SUM(payments) AS total_payments, 
            SUM(outstanding_debts) AS total_outstanding_debt
            FROM received_stock
            WHERE date BETWEEN %s AND %s
            GROUP BY date, product_type, vendor, quantity, rate_per_litre
        ''', (start_date, end_date))
        received_stock_data = cursor.fetchall()

        # Total sales and margin
        cursor.execute(''' 
            SELECT p.pump_name, pp.product_type, 
                   SUM(ps.sales_litres * pp.price) AS total_sales_value,
                   SUM(ps.sales_litres * (pp.price - rs.rate_per_litre)) AS total_margin
            FROM (
                SELECT * FROM pump_sales 
                UNION ALL 
                SELECT * FROM pump_sales_afternoon
            ) AS ps
            JOIN pumps p ON ps.pump_id = p.id
            JOIN received_stock rs ON p.product_type = rs.product_type
            JOIN product_prices pp ON p.product_type = pp.product_type
            WHERE ps.date BETWEEN %s AND %s
            GROUP BY p.pump_name, pp.product_type
        ''', (start_date, end_date))
        sales_data = cursor.fetchall()

        # Total customer credits with customer details
        cursor.execute(''' 
        SELECT customer_name, SUM(credit_amount), SUM(debit_amount),
        (SUM(credit_amount) - SUM(debit_amount)) AS total_customer_debt_status
        FROM customer_credit
        WHERE DATE(created_at) BETWEEN %s AND %s
        GROUP BY customer_name, customer_credit.created_at
        ''', (start_date, end_date))
        customer_credits_data = cursor.fetchall()

        # Total MD transactions
        cursor.execute(''' 
            SELECT
                SUM(CASE WHEN mt.transaction_type = 'credit' THEN mt.amount ELSE 0 END) AS md_credits,
                SUM(CASE WHEN mt.transaction_type = 'debit' THEN mt.amount ELSE 0 END) AS md_debits
            FROM md_transactions mt
            WHERE mt.created_at BETWEEN %s AND %s
        ''', (start_date, end_date))
        md_transactions_data = cursor.fetchone()

        # Get the latest closing stock value for each pump within the date range
        cursor.execute(''' 
            SELECT u.closing_stock, pp.price, p.product_type
            FROM underground u 
            JOIN pumps p ON u.tank_id = p.id
            JOIN product_prices pp ON p.product_type = pp.product_type
            WHERE u.date = (SELECT MAX(date) FROM underground WHERE date BETWEEN %s AND %s)
        ''', (start_date, end_date))
        available_stock_data = cursor.fetchall()


        conn.close()

        # Ensure None values are handled as 0
        def handle_none(val):
            return val if val is not None else 0

        # Total calculations (keeping sums intact)
        total_received_stock_value = sum(handle_none(row[5]) for row in received_stock_data)
        total_sales_value = sum(handle_none(row[2]) for row in sales_data)
        total_payments = sum(handle_none(row[6]) for row in received_stock_data)
        total_outstanding_debt = sum(handle_none(row[7]) for row in received_stock_data)
        total_md_credits = handle_none(md_transactions_data[0])
        total_md_debits = handle_none(md_transactions_data[1])

        total_customer_debt_status = sum(handle_none(row[3]) for row in customer_credits_data)

        # Available stock value calculation (closing_stock * price) for each product type
        product_revenue_data = {}

        for row in sales_data:
            product_type = row[1]  # Extract product type
            sales_value = handle_none(row[2])

            # Find the corresponding available stock value per product type
            available_stock_value = 0
            for stock_row in available_stock_data:
                if stock_row[2] == product_type:
                    closing_stock = handle_none(stock_row[0])
                    price = handle_none(stock_row[1])
                    available_stock_value += closing_stock * price

            # Calculate total revenue and margin per product
            total_margin = handle_none(row[3])
            total_product_revenue = sales_value + available_stock_value

            # Store the data in the dictionary
            product_revenue_data[product_type] = {
                "revenue": total_product_revenue,
                "margin": total_margin
            }

        # Overall total revenue (sum of all product revenues)
        total_revenue = sum(item["revenue"] for item in product_revenue_data.values())

        # Pass all data to the template
        return render_template('business_position.html', 
        received_stock_data=received_stock_data,
        sales_data=sales_data,
        customer_credits_data=customer_credits_data,
        md_transactions_data=md_transactions_data,
        total_received_stock_value=total_received_stock_value,
        total_sales_value=total_sales_value,
        total_revenue=total_revenue,
        product_revenue_data=product_revenue_data,
        total_expenses=(total_payments + total_outstanding_debt + total_customer_debt_status + total_md_debits),
        profit_or_loss=(total_revenue - (total_payments + total_outstanding_debt + total_customer_debt_status + total_md_debits) + total_md_credits),
        
        total_payments=total_payments,
        total_outstanding_debt=total_outstanding_debt,)

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard_2'))
    

    


@app.route('/customer_credit_log', methods=['GET'])
def customer_credit_log():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch start and end dates from request args, if provided
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = """
        SELECT customer_name, credit_amount, debit_amount, status, remark, created_at
        FROM customer_credit_log ORDER BY created_at DESC
    """
    
    if start_date and end_date:
        try:
            cursor.execute("""SELECT customer_name, credit_amount, debit_amount, status, remark, created_at
            FROM customer_credit_log
            WHERE DATE(created_at) BETWEEN %s AND %s;""", (start_date, end_date))
        except Exception as e:
            flash(f"Error: {str(e)}", 'danger')
    else:
        cursor.execute(query)
    
    logs = cursor.fetchall()

    #Total outstanding
    total_outstanding_credit = sum(log[1] - log[2] for log in logs)

    cursor.close()
    conn.close()


    
    return render_template('customer_credit_log.html', logs=logs, total_outstanding_credit=total_outstanding_credit)







#Route to get received stock data for the select options
@app.route('/get_received_stock', methods=['GET'])
def get_received_stock():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, product_type, vendor, outstanding_debts, date
        FROM received_stock
        WHERE outstanding_debts > 0
    """)
    stock_data = cursor.fetchall()

    # Structure the data to return in JSON format
    stock_list = [{
        'id': row[0],
        'product_type': row[1],
        'vendor': row[2],
        'outstanding_debts': row[3],
        'date': row[4]
    } for row in stock_data]

    cursor.close()
    conn.close()
    return jsonify(stock_list)

# Route to update payment and outstanding debts
@app.route('/update_payment', methods=['GET', 'POST'])
def update_payment():

    if request.method == 'POST':
        try:
            data = request.json
            vendor = data['vendor']
            product_type = data['product_type']
            payment = data['payment']
            new_outstanding = data['new_outstanding']

            conn = get_db_connection()
            cursor = conn.cursor()

            # Update the received stock based on product_type and vendor
            cursor.execute("""
                UPDATE received_stock
                SET payments = payments + %s, outstanding_debts = %s
                WHERE product_type = %s AND vendor = %s
            """, (payment, new_outstanding, product_type, vendor))

            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'message': 'Payment updated successfully!'})
        except Exception as e:
            flash(f"Error: {str(e)}," "danger")
            return render_template('update_payment.html')
    else:
        return render_template('update_payment.html')




        
if __name__ == '__main__':
    app.run(debug=True)
