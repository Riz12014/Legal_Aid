from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask import Flask, redirect, render_template, request, session, url_for, flash, jsonify
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import os
import pyotp
import qrcode
import base64
from io import BytesIO
#from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__) 
app.secret_key = 'Reyn@1052'
s = URLSafeTimedSerializer(app.secret_key)
# = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'dattebayo12086@gmail.com'
app.config['MAIL_PASSWORD'] = 'qkmt eqqb fvvy oijr' #App Pass

mail = Mail(app)


db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'legal_aid',
    'port': '3306'
}

def create_connection():
    return mysql.connector.connect(**db_config)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['Email']
        password = request.form['password']
        
        try:
            db = create_connection()
            cursor = db.cursor(dictionary=True)
            
            query = "SELECT * FROM Admin WHERE Email = %s AND Password = %s"
            cursor.execute(query, (email, password))
            admin = cursor.fetchone()
            
            cursor.close()
            db.close()
            
            if admin:
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid email or password', 'error')
        except Error as e:
            flash(f"Database error: {str(e)}", 'error')
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_type = request.form['userType']

        full_name = request.form['fullName']
        date_of_birth = request.form['DateofBrith']
        contact_no = request.form['contactNo']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        gender = request.form['gender']
        national_id = request.form['nationalID']
        address_house = request.form['house']
        address_street = request.form['street']
        address_area = request.form['area']
        address_city = request.form['city']
        email = request.form['email']

        if password != confirm_password:
            return render_template('register.html', error_message="Passwords do not match.")

        hashed_password = generate_password_hash(password)

        if user_type == 'lawyer':
            bar_association_number = request.form['barNumber']
            specialized_fields = request.form['specialized_Feilds']
            office_address = request.form['office_Address']
            consultation_fee = request.form['consultationFee']

            query = """
                INSERT INTO User (
                    UserType, FullName, DateofBirth, ContactNo, Password, Gender, NationalID,
                    AddressHouse, AddressStreet, AddressArea, AddressCity, Email, BarNumber, SpecializedFeilds, OfficeAddress, ConsultationFee
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            params = (
                user_type, full_name, date_of_birth, contact_no, hashed_password, gender, national_id,
                address_house, address_street, address_area, address_city, email, bar_association_number,
                specialized_fields, office_address, consultation_fee
            )
        elif user_type == 'customer':
            query = """
                INSERT INTO User (
                    UserType, FullName, DateofBirth, ContactNo, Password, Gender, NationalID,
                    AddressHouse, AddressStreet, AddressArea, AddressCity, Email
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            params = (
                user_type, full_name, date_of_birth, contact_no, hashed_password, gender, national_id,
                address_house, address_street, address_area, address_city, email
            )
        
        try:
            db = create_connection()
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
            cursor.close()
            db.close()

            return render_template('login.html', success_message=f'Registration Successfully Done as a {user_type.capitalize()}!')
        except Error as e:
            return render_template('register.html', error_message=f"Error: {str(e)}")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['Email']
        password = request.form['password']

        query = "SELECT * FROM User WHERE Email = %s"
        params = (email,)
        
        db = create_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute(query, params)
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user and check_password_hash(user['Password'], password):
            session['user_id'] = user['ID']
            session['user_type'] = user['UserType']
            
        if user and check_password_hash(user['Password'], password):
            session['user_id'] = user['ID'] 
            session['user_type'] = user['UserType'].lower() 
            
            if session['user_type'] == 'lawyer': 
                return redirect(url_for('lawyer_dashboard'))
            elif session['user_type'] == 'customer': 
                return redirect(url_for('customer_dashboard'))
            elif session['user_type'] == 'admin': 
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'error') 
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/lawyer_dashboard')
def lawyer_dashboard():
    if 'user_id' in session and session['user_type'] == 'lawyer':
        return render_template('lawyer_dashboard.html')
    else:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

@app.route('/customer_dashboard', methods=['GET', 'POST'])
def customer_dashboard():
    # Ensure the user is logged in and is a customer
    if 'user_id' in session and session['user_type'] == 'customer':
        search_results = []

        # Handle form submission for searching crimes
        if request.method == 'POST':
            search_query = request.form.get('search_query', '').strip()
            
            # Ensure the search query is not empty
            if search_query:
                try:
                    # Establish a database connection
                    db = create_connection()
                    cursor = db.cursor(dictionary=True)
                    
                    # Execute a query to search for matching crimes in the 'laws' table
                    query = "SELECT Crime, Law FROM laws WHERE Crime LIKE %s"
                    cursor.execute(query, (f'%{search_query}%',))
                    
                    # Fetch all matching records
                    search_results = cursor.fetchall()
                    
                    # Notify user if no results are found
                    if not search_results:
                        flash("No matching laws found for the search term.", 'info')

                except Error as e:
                    # Handle any database errors
                    flash(f"Database error: {str(e)}", 'error')

                finally:
                    # Close the database cursor and connection
                    cursor.close()
                    db.close()
            else:
                # Flash a warning message if the search query is empty
                flash("Please enter a valid search term.", 'warning')
        
        # Render the customer dashboard template with the search results
        return render_template('customer_dashboard.html', search_results=search_results)
    
    else:
        # Redirect unauthorized users to the login page
        flash("Unauthorized access. Please log in as a customer.", 'error')
        return redirect(url_for('login'))

def send_reset_email(email):
    token = s.dumps(email, salt='password-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request',
                  sender='noreply@yourdomain.com',
                  recipients=[email])
    msg.body = f'''To reset your password, click the following link:
{reset_url}

If you did not request this, simply ignore this email and no changes will be made.

This link will expire in 1 hour.
'''
    mail.send(msg)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        db = create_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM User WHERE Email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user:
            send_reset_email(email)
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('No account found with that email address.', 'error')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        db = create_connection()
        cursor = db.cursor()
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE User SET Password = %s WHERE Email = %s", (hashed_password, email))
        db.commit()
        cursor.close()
        db.close()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)
 
@app.route('/see_lawyers_list', methods=['GET', 'POST'])
def see_lawyers_list():
    if request.method == 'GET':
        try:
            query = "SELECT * FROM User WHERE UserType = 'lawyer'"
            db = create_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(query)
            lawyers = cursor.fetchall()
        except Exception as e:
            print(f"An error occurred: {e}")
            lawyers = []
        finally:
            cursor.close()
            db.close()
        
        for lawyer in lawyers:
            print(f"Lawyer Bar Number: {lawyer['BarNumber']}")
        
        return render_template('see_lawyers_list.html', lawyers=lawyers)
    
@app.route('/admin_see_lawyers_list', methods=['GET', 'POST'])
def admin_see_lawyers_list():
    if request.method == 'GET':
        try:
            query = "SELECT * FROM User WHERE UserType = 'lawyer'"
            db = create_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(query)
            lawyers = cursor.fetchall()
        except Exception as e:
            print(f"An error occurred: {e}")
            lawyers = [] 
        finally:
            cursor.close()
            db.close()
        
        return render_template('admin_see_lawyers.html', lawyers=lawyers)

@app.route('/admin_see_customer_list', methods=['GET', 'POST'])
def admin_see_customer_list():
    if request.method == 'GET':
        try:
            query = "SELECT * FROM User WHERE UserType = 'customer'"
            db = create_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(query)
            customers = cursor.fetchall()
        except Exception as e:
            print(f"An error occurred: {e}")
            customers = [] 
        finally:
            cursor.close()
            db.close()
        
        return render_template('admin_see_customer.html', customers=customers)

@app.route('/post_my_case', methods=['GET', 'POST'])
def post_my_case():
    if request.method == 'POST':
        
        title = request.form.get('Title')
        brief_description = request.form.get('Brief_Description')
        category = request.form.get('Category')
        subcategory = request.form.get('Subcategory')
        city = request.form.get('City')
        full_description = request.form.get('Full_Description')

        query = """
            INSERT INTO post_cases (
                Title_of_Case_Listing, Brief_Description, Pick_a_Category, Sub_category, City, Full_Description
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (
            title, brief_description, category, subcategory, city, full_description
        )
    
        try:
            db = create_connection()
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
            cursor.close()
            db.close()
            
            return render_template('post_my_case.html', success_message='Your Case Has Been Posted Successfully, Thank you for your patience')
        except Exception as e:
            return render_template('post_my_case.html', error_message=f'An error occurred: {str(e)}')
    
    return render_template('post_my_case.html')

@app.route('/pending', methods=['GET', 'POST'])
def pending():
    if request.method == 'GET':
        try:
            query = "SELECT * FROM post_cases"
            db = create_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute(query)
            cases = cursor.fetchall()  # Changed variable name from 'lawyers' to 'cases'
        except Exception as e:
            print(f"An error occurred: {e}")
            cases = []  # Changed variable name from 'lawyers' to 'cases'
        finally:
            cursor.close()
            db.close()
            
        return render_template('pending.html', cases=cases)  # Changed 'lawyers' to 'cases'
    
@app.route('/favorite_lawyer', methods=['GET', 'POST'])
def favorite_lawyer():
    if request.method == 'POST':
        customer_name = request.form['FullName']
        bar_number = request.form['BarNumber']
        rating = request.form['Rating']
        review = request.form['Review']
        
        query = """
        INSERT INTO Rating (
        FullName, LawyerBarNumber, Rating, Review
        )
        VALUES (%s, %s, %s, %s)
        """
        params = (customer_name, bar_number, rating, review)
        
        try:
            db = create_connection()
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
            cursor.close()
            db.close()
            
            flash('Lawyer added to favorites successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    
    return render_template('favorite_lawyer.html', bar_number=bar_number)

@app.route('/rate_lawyer/<bar_number>', methods=['GET', 'POST'])
def rate_lawyer(bar_number):
    if request.method == 'POST':
        customer_name = request.form['FullName']
        rating = request.form['Rating']
        review = request.form['Review']
        
        query = """
        INSERT INTO Rating (
        FullName, LawyerBarNumber, Rating, Review
        )
        VALUES (%s, %s, %s, %s)
        """
        params = (customer_name, bar_number, rating, review)
        
        try:
            db = create_connection()
            cursor = db.cursor()
            cursor.execute(query, params)
            db.commit()
            cursor.close()
            db.close()
            
            flash('Lawyer rated successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    
    # For GET requests, just render the template
    return render_template('rate_lawyer.html', bar_number=bar_number)

def generate_totp_secret():
    return pyotp.random_base32()

def generate_totp_uri(email, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(email, issuer_name="LegalAid")

def generate_qr_code(uri):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = create_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        secret = session.get('totp_secret')

        if pyotp.TOTP(secret).verify(totp_code):
            # Save the secret to the database
            cursor.execute("UPDATE User SET TOTPSecret = %s WHERE ID = %s", (secret, user_id))
            db.commit()
            flash('Two-factor authentication has been set up successfully!', 'success')
            return redirect(url_for('customer_dashboard')) 
        else:
            flash('Invalid code. Please try again.', 'error')

  
    secret = generate_totp_secret()
    session['totp_secret'] = secret

    
    cursor.execute("SELECT Email FROM User WHERE ID = %s", (user_id,))
    user = cursor.fetchone()
    email = user['Email']

    
    uri = generate_totp_uri(email, secret)
    qr_code = generate_qr_code(uri)

    cursor.close()
    db.close()

    return render_template('setup_2fa.html', qr_code=qr_code, secret=secret)

if __name__ == '__main__':
    app.run(debug=True)