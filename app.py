from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_mail import Mail, Message
import plotly.graph_objects as go
import os
import json
import random
import string
import hashlib
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from user_agents import parse
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set a secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configure session to use filesystem
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Create instance directory if it doesn't exist
if not os.path.exists('instance'):
    os.makedirs('instance')

# Database configuration
if os.environ.get('FLASK_ENV') == 'production':
    # Use PostgreSQL in production (Render)
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
    else:
        # Fallback to SQLite if no DATABASE_URL is provided
        database_url = 'sqlite:///' + os.path.join(app.instance_path, 'billing.db')
else:
    # Use SQLite in development
    database_url = 'sqlite:///' + os.path.join(app.instance_path, 'billing.db')

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'pramodalmel@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password-here')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'pramodalmel@gmail.com')

# Production configuration
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Print mail configuration
print("\nMail Configuration:")
print(f"Server: {app.config['MAIL_SERVER']}")
print(f"Port: {app.config['MAIL_PORT']}")
print(f"TLS: {app.config['MAIL_USE_TLS']}")
print(f"SSL: {app.config['MAIL_USE_SSL']}")
print(f"Username: {app.config['MAIL_USERNAME']}")
print(f"Password set: {'Yes' if app.config['MAIL_PASSWORD'] else 'No'}")
print(f"Default Sender: {app.config['MAIL_DEFAULT_SENDER']}")

# Initialize extensions
db = SQLAlchemy(app)  # Flask-SQLAlchemy
mail = Mail(app)  # Flask-Mail
Session(app)  # Flask-Session

# Add template context processor for current year
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Send OTP via email
def send_otp_email(user_email, otp):
    try:
        msg = Message(
            'Your OTP for Praveen Jewellers Admin Login',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user_email]
        )
        msg.body = f'''Your OTP for Praveen Jewellers Admin Login is: {otp}

This OTP will expire in 10 minutes.

If you did not request this OTP, please ignore this email.'''
        
        print(f"Sending email to {user_email} with OTP {otp}")
        mail.send(msg)
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

# Ensure database and tables exist
def init_db():
    try:
        with app.app_context():
            db.create_all()
            create_admin_user()
            print("Database initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise

# Database models
class Billing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(10), nullable=False)
    item = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    discount = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='draft')  # 'draft' or 'final'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('bills', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, default=False)

class TrustedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    device_id = db.Column(db.String(64), nullable=False)  # Hash of user agent + IP
    last_used = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Helper functions
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def generate_device_hash(request):
    user_agent = request.user_agent.string
    ip_address = request.remote_addr
    device_hash = hashlib.sha256(f"{user_agent}{ip_address}".encode()).hexdigest()
    return device_hash

def get_device_id():
    """Generate a unique device ID based on user agent and IP"""
    user_agent = request.user_agent.string
    ip_address = request.remote_addr
    device_id = hashlib.sha256(f"{user_agent}{ip_address}".encode()).hexdigest()
    return device_id

def send_otp_email(user_email, otp):
    """Send OTP via email using Flask-Mail"""
    try:
        # Validate email configuration
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            print("\nError: Email credentials not configured")
            print(f"Username: {app.config['MAIL_USERNAME']}")
            print(f"Password set: {'Yes' if app.config['MAIL_PASSWORD'] else 'No'}")
            return False

        print("\nAttempting to send email...")
        print(f"From: {app.config['MAIL_DEFAULT_SENDER']}")
        print(f"To: {user_email}")

        # Create email message
        msg = Message(
            subject='Your OTP for Jewel Box Admin Login',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user_email]
        )
        msg.body = f'''Your OTP for Jewel Box Admin Login is: {otp}

This OTP will expire in 10 minutes.

If you did not request this OTP, please ignore this email.'''

        # Send email
        mail.send(msg)
        print("\nEmail sent successfully!")
        return True

    except Exception as e:
        print("\nEmail Error Details:")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        return False

def verify_device(user_id):
    """Check if the current device is trusted"""
    device_id = get_device_id()
    trusted_device = TrustedDevice.query.filter_by(
        user_id=user_id,
        device_id=device_id
    ).first()
    
    if trusted_device:
        trusted_device.last_used = datetime.utcnow()
        db.session.commit()
        return True
    return False

def save_device(user_id):
    """Save current device as trusted"""
    device_id = get_device_id()
    new_device = TrustedDevice(
        user_id=user_id,
        device_id=device_id
    )
    db.session.add(new_device)
    db.session.commit()

def get_time_range(time_period):
    today = datetime.today()
    if time_period == "daily":
        start_date = today.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "weekly":
        start_date = today - timedelta(days=today.weekday())
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "monthly":
        start_date = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "yearly":
        start_date = today.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return start_date.strftime("%Y-%m-%d")

def create_admin_user():
    """Create or update the admin user with hardcoded credentials"""
    try:
        # Delete all existing admin users
        User.query.filter_by(role='admin').delete()
        
        # Create new admin with hardcoded credentials
        admin = User(
            username='jewel_admin',  # Hardcoded admin username
            email='pramodalmel@gmail.com',  # Hardcoded admin email
            password=generate_password_hash('JewelBox@2024'),  # Hardcoded admin password
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    except Exception as e:
        print(f"Error creating admin user: {e}")

def standardize_item_name(item_name):
    # Dictionary of standard names
    standard_names = {
        'ring': 'Ring',
        'rings': 'Ring',
        'necklace': 'Necklace',
        'necklaces': 'Necklace',
        'bracelet': 'Bracelet',
        'bracelets': 'Bracelet',
        'earring': 'Earring',
        'earrings': 'Earring',
        'chain': 'Chain',
        'chains': 'Chain',
        'pendant': 'Pendant',
        'pendants': 'Pendant'
    }
    
    # Convert to lowercase for comparison
    item_lower = item_name.lower().strip()
    
    # Return standardized name if it exists, otherwise return original with first letter capitalized
    return standard_names.get(item_lower, item_name.strip().title())

def require_admin():
    if 'username' not in session:
        flash("Please login first!", "error")
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.role != 'admin':
        flash("Access denied. Admin rights required.", "error")
        return redirect(url_for('home'))
    return None

# Route protection helpers
def require_user():
    if not session.get('logged_in') or 'username' not in session:
        session.clear()
        flash("Please login first!", "error")
        return redirect(url_for('login'))
    
    # Verify user still exists in database
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.clear()
        flash("User account not found. Please login again.", "error")
        return redirect(url_for('login'))
    return None

def require_no_admin():
    # Verify user is logged in and not an admin
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('role') == 'admin':
        return redirect(url_for('billing'))
    return None



# Routes
@app.route("/about")
def about():
    check = require_user()
    if check: return check
    return render_template('about.html', username=session.get('username'))
    
@app.route("/contact")
def contact():
    check = require_user()
    if check: return check
    return render_template("contact.html", username=session.get('username'))

@app.route("/", methods=["GET", "POST"])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    # For admin users, show billing dashboard
    if session.get('role') == 'admin':
        time_period = request.args.get("time_period", "daily")
        start_date = get_time_range(time_period)
        
        # Get billing data for admin
        billing_data = Billing.query.filter(
            Billing.date >= start_date,
            Billing.user_id == session['user_id']
        ).all()
        
        # Calculate metrics
        today = datetime.today().strftime("%Y-%m-%d")
        daily_revenue = sum(bill.total_price for bill in billing_data if bill.date == today)
        daily_bills = len([bill for bill in billing_data if bill.date == today])
        
        # Monthly revenue
        monthly_start = datetime.today().replace(day=1).strftime("%Y-%m-%d")
        monthly_revenue = sum(bill.total_price for bill in Billing.query.filter(
            Billing.date >= monthly_start,
            Billing.user_id == session['user_id']
        ).all())

        # Create charts
        items = {}
        for bill in billing_data:
            if bill.item not in items:
                items[bill.item] = bill.total_price
            else:
                items[bill.item] += bill.total_price

        pie_chart_fig = go.Figure(data=[go.Pie(labels=list(items.keys()), values=list(items.values()), hole=0.3)])
        pie_chart_fig.update_layout(
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            margin=dict(t=80, b=40, l=0, r=0),  # Reduced left and right margins
            height=400, width=600,  # Increased width for better visibility
            title=dict(text="Sales Distribution", x=0.5, y=0.95, xanchor="center", yanchor="top"),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
        )
        pie_chart_html = pie_chart_fig.to_html(full_html=False, config={'displayModeBar': False})

        dates = [datetime.strptime(bill.date, "%Y-%m-%d").date() for bill in billing_data]
        total_prices = [bill.total_price for bill in billing_data]
        scatter_fig = go.Figure(data=[go.Scatter(
            x=dates, y=total_prices, mode='markers+lines',
            marker=dict(size=10, color='rgba(255, 99, 132, 0.6)'),
            line=dict(color='rgba(255, 99, 132, 0.6)')
        )])
        scatter_fig.update_layout(
            title_text="Sales Trend", title_x=0.5,
            xaxis_title="Date", yaxis_title="Amount (₹)",
            xaxis=dict(type="category")
        )
        scatter_html = scatter_fig.to_html(full_html=False)

        return render_template("index.html", 
                          pie_chart=pie_chart_html, 
                          scatter_plot=scatter_html,
                          username=session['username'],
                          daily_bills=daily_bills,
                          daily_revenue="{:.2f}".format(daily_revenue),
                          monthly_revenue="{:.2f}".format(monthly_revenue),
                          time_period=time_period)
    
    # For regular users, show the showcase dashboard
    check = require_no_admin()
    if check:
        return check
    return render_template("user_dashboard.html", username=session['username'])

@app.route("/billing", methods=["GET", "POST"])
def billing():
    admin_check = require_admin()
    if admin_check is not None:
        return admin_check

    if request.method == "POST":
        name = request.form["name"]
        contact = request.form["contact"]
        address = request.form["address"]
        date = request.form["date"]
        items = [standardize_item_name(item) for item in request.form.getlist("item")]
        quantities = list(map(int, request.form.getlist("quantity")))
        prices = list(map(float, request.form.getlist("price")))
        discounts = list(map(float, request.form.getlist("discount")))
        taxes = list(map(float, request.form.getlist("tax")))
        is_draft = 'save_draft' in request.form

        bill_id = f"bill_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        for i in range(len(items)):
            subtotal = quantities[i] * prices[i]
            discount_amount = subtotal * (discounts[i] / 100)
            tax_amount = subtotal * (taxes[i] / 100)
            total_price = subtotal - discount_amount + tax_amount

            new_billing = Billing(
                bill_id=bill_id,
                user_id=session['user_id'],
                name=name, 
                contact=contact, 
                address=address, 
                date=date,
                item=items[i], 
                quantity=quantities[i], 
                price=prices[i],
                discount=discounts[i], 
                tax=taxes[i], 
                total_price=total_price,
                status='draft' if is_draft else 'final'
            )
            db.session.add(new_billing)

        db.session.commit()
        
        if is_draft:
            flash("Bill saved as draft. Please update it to final when ready.", "info")
        else:
            flash("Bill created successfully!", "success")
            
        return redirect(f"/bill/{bill_id}")
    
    return render_template("billing_form.html")

@app.route("/bill/update_status/<bill_id>", methods=["POST"])
def update_bill_status(bill_id):
    admin_check = require_admin()
    if admin_check is not None:
        return admin_check
        
    if request.method == "POST":
        # Update all items with this bill_id to status='final'
        Billing.query.filter_by(bill_id=bill_id).update({
            'status': 'final',
            'updated_at': datetime.utcnow()
        }, synchronize_session=False)
        db.session.commit()
        
        flash("Bill status updated to final. It will now appear in reports and analytics.", "success")
        return redirect(f"/bill/{bill_id}")
    
    return redirect(url_for('billing'))

@app.route("/bill/<string:bill_id>", methods=["GET", "POST"])
def bill(bill_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        # Update existing bill
        billing_data = Billing.query.filter_by(bill_id=bill_id).all()
        if not billing_data:
            flash("Bill not found!", "error")
            return redirect(url_for('home'))

        # Delete old entries
        for entry in billing_data:
            db.session.delete(entry)
        
        # Create new entries
        name = request.form["name"]
        contact = request.form["contact"]
        address = request.form["address"]
        date = request.form["date"]
        items = [standardize_item_name(item) for item in request.form.getlist("item")]
        quantities = list(map(int, request.form.getlist("quantity")))
        prices = list(map(float, request.form.getlist("price")))
        discounts = list(map(float, request.form.getlist("discount")))
        taxes = list(map(float, request.form.getlist("tax")))

        for i in range(len(items)):
            subtotal = quantities[i] * prices[i]
            discount_amount = subtotal * (discounts[i] / 100)
            tax_amount = subtotal * (taxes[i] / 100)
            total_price = subtotal - discount_amount + tax_amount

            new_billing = Billing(
                bill_id=bill_id,
                user_id=session['user_id'],
                name=name, contact=contact, address=address, date=date,
                item=items[i], quantity=quantities[i], price=prices[i],
                discount=discounts[i], tax=taxes[i], total_price=total_price
            )
            db.session.add(new_billing)

        db.session.commit()
        flash("Bill updated successfully!", "success")
        return redirect(f"/bill/{bill_id}")

    billing_data = Billing.query.filter_by(bill_id=bill_id, user_id=session['user_id']).all()
    if not billing_data:
        flash("Bill not found!", "error")
        return redirect(url_for('home'))

    total_amount = sum(item.total_price for item in billing_data)
    return render_template("bill.html", 
                         billing_data=billing_data, 
                         total_amount=total_amount)

@app.route("/login", methods=["GET", "POST"])
def login():
    # Clear any existing session first
    session.clear()
    
    if request.method == "POST":
        try:
            username = request.form.get("username")
            password = request.form.get("password")
            
            if not username or not password:
                flash("Please provide both username and password", "error")
                return render_template("login.html")
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                if user.role == 'admin':
                    flash("Please use admin login for admin access", "error")
                    return redirect(url_for('admin_login'))
                
                # Set session data
                session.clear()
                session['username'] = username
                session['user_id'] = user.id
                session['role'] = user.role
                session['logged_in'] = True
                session.permanent = True
                
                # Force session to be saved
                session.modified = True
                
                flash("Login successful!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid username or password", "error")
        except Exception as e:
            flash("An error occurred during login. Please try again.", "error")
            print(f"Login error: {str(e)}")
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form["username"]
        email = request.form.get("email")  # Made email optional
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")
        
        # Username validation
        if len(username) < 4:
            flash("Username must be at least 4 characters long!", "error")
            return render_template("signup.html")
        if not username.isalnum():
            flash("Username can only contain letters and numbers!", "error")
            return render_template("signup.html")
            
        # Email validation and handling (only if provided)
        if email:
            base_email = email
            counter = 1
            while User.query.filter_by(email=email).first():
                # If email exists, add a number suffix before the @ symbol
                email_name, domain = base_email.split('@')
                email = f"{email_name}{counter}@{domain}"
                counter += 1
            
        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "error")
            return render_template("signup.html")
        if not any(c.isupper() for c in password):
            flash("Password must contain at least one uppercase letter!", "error")
            return render_template("signup.html")
        if not any(c.islower() for c in password):
            flash("Password must contain at least one lowercase letter!", "error")
            return render_template("signup.html")
        if not any(c.isdigit() for c in password):
            flash("Password must contain at least one number!", "error")
            return render_template("signup.html")
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            flash("Password must contain at least one special character!", "error")
            return render_template("signup.html")
            
        if password != confirm_password:
            flash("Passwords don't match!", "error")
            return render_template("signup.html")
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return render_template("signup.html")
            
        # Create new user
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password, role='user')
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while creating your account. Please try again.", "error")
            print(f"Signup error: {str(e)}")
            return render_template("signup.html")
    
    return render_template("signup.html")

@app.route("/logout")
def logout():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            # Only clear bills for admin logout
            Billing.query.filter_by(user_id=session['user_id']).delete()
            db.session.commit()
    session.clear()  # Clear all session data
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/clear_history')
def clear_history():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        # Delete only current user's billing records
        Billing.query.filter_by(user_id=session['user_id']).delete()
        db.session.commit()
        flash("Your billing history has been cleared successfully!", "success")
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"Error clearing history: {str(e)}", "error")
        return redirect(url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        print(f"Login attempt - Username: {username}, Email: {email}")

        # Clear any existing session data
        session.clear()

        # Check for admin user
        user = User.query.filter_by(username=username, role='admin').first()

        if not user:
            flash('Invalid username', 'error')
            return render_template('admin_login.html')

        if not check_password_hash(user.password, password):
            flash('Invalid password', 'error')
            return render_template('admin_login.html')

        if user.email.lower() != email.lower():
            flash('Invalid email address', 'error')
            return render_template('admin_login.html')

        # Skip OTP for pramodalmel@gmail.com
        if user.email.lower() == 'pramodalmel@gmail.com':
            # Set session data
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = 'admin'
            session['logged_in'] = True
            session.permanent = True
            # Save device as trusted
            save_device(user.id)
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('billing'))
            
        # Check if device is trusted for other admin users
        if verify_device(user.id):
            # Set session data for trusted device
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = 'admin'
            session['logged_in'] = True
            session.permanent = True
            flash('Welcome back, Admin!', 'success')
            return redirect(url_for('billing'))

        try:
            # Generate and store OTP
            otp = ''.join(random.choices(string.digits, k=6))
            expires_at = datetime.utcnow() + timedelta(minutes=10)

            print(f"Generated OTP: {otp} for user {username}")

            # Delete any existing unverified OTPs
            OTP.query.filter_by(user_id=user.id, verified=False).delete()

            # Create new OTP record
            new_otp = OTP(
                user_id=user.id,
                otp=otp,
                expires_at=expires_at
            )
            db.session.add(new_otp)
            db.session.commit()

            # Send OTP via email
            if send_otp_email(email, otp):
                # Store user_id temporarily for OTP verification
                session['temp_user_id'] = user.id
                session['admin_email'] = email
                flash(f'OTP has been sent to {email}', 'success')
                return redirect(url_for('verify_otp'))
            else:
                db.session.rollback()
                flash('Failed to send OTP. Please try again.', 'error')
                return render_template('admin_login.html')

        except Exception as e:
            db.session.rollback()
            print(f'Error during OTP process: {str(e)}')
            flash('An error occurred. Please try again.', 'error')
            return render_template('admin_login.html')

    # For GET request, show login form
    return render_template('admin_login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Check if user has logged in and is waiting for OTP verification
    if 'temp_user_id' not in session or 'admin_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        user_id = session.get('temp_user_id')

        # Get the most recent unverified OTP for the user
        otp_record = OTP.query.filter_by(
            user_id=user_id,
            verified=False
        ).order_by(OTP.created_at.desc()).first()

        if not otp_record:
            flash('OTP not found or expired. Please try again.', 'error')
            return redirect(url_for('admin_login'))

        if otp_record.expires_at < datetime.utcnow():
            flash('OTP has expired. Please request a new one.', 'error')
            return redirect(url_for('admin_login'))

        if entered_otp != otp_record.otp:
            flash('Invalid OTP. Please try again.', 'error')
            return render_template('verify_otp.html')

        try:
            # Mark OTP as verified
            otp_record.verified = True

            # Get user details
            user = User.query.get(user_id)

            # Set session data
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = 'admin'
            session['logged_in'] = True
            session.permanent = True

            # Save device hash if remember device is checked
            if request.form.get('remember_device'):
                device_hash = generate_device_hash(request)
                new_device = TrustedDevice(
                    user_id=user.id,
                    device_id=device_hash,
                    last_used=datetime.utcnow()
                )
                db.session.add(new_device)

            db.session.commit()

            # Clear temporary session data
            session.pop('temp_user_id', None)
            session.pop('admin_email', None)

            flash('Login successful!', 'success')
            return redirect(url_for('billing'))

        except Exception as e:
            db.session.rollback()
            print(f'Error during OTP verification: {str(e)}')
            flash('An error occurred. Please try again.', 'error')
            return render_template('verify_otp.html')

    # Show OTP verification page with email address
    flash(f'OTP has been sent to {session.get("admin_email")}', 'info')
    return render_template('verify_otp.html')

@app.route('/resend-otp')
def resend_otp():
    if 'temp_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('admin_login'))

    # Generate new verification code
    verification_code = ''.join(random.choices(string.digits, k=6))
    
    # Update session with new code
    session['verification_code'] = verification_code
    session['code_expires'] = (datetime.utcnow() + timedelta(minutes=10)).timestamp()

    # Show new verification code
    flash(f'Your new verification code is: {verification_code}', 'info')
    OTP.query.filter_by(user_id=user.id, verified=False).delete()
    
    new_otp = OTP(
        user_id=user.id,
        otp=otp,
        expires_at=expires_at
    )
    db.session.add(new_otp)
    db.session.commit()
    
    # Send new OTP via email
    if send_otp_email(user.email, otp):
        flash("A new OTP has been sent to your email", "success")
    else:
        flash("Failed to send OTP. Please try again.", "error")
    
    return redirect(url_for('verify_otp'))

@app.route("/delete_account", methods=["GET", "POST"])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    if request.method == "POST":
        password = request.form.get("password")
        user = User.query.filter_by(username=session['username']).first()
        
        if user and check_password_hash(user.password, password):
            try:
                # Delete all user's billing records first
                Billing.query.filter_by(user_id=user.id).delete()
                # Delete the user
                db.session.delete(user)
                db.session.commit()
                session.clear()  # Clear the session
                flash("Your account has been successfully deleted.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash("An error occurred while deleting your account.", "error")
                print(f"Account deletion error: {str(e)}")
        else:
            flash("Invalid password.", "error")
    
    return render_template("delete_account.html")

# Initialize database and create admin user
with app.app_context():
    try:
        # Ensure instance directory exists
        instance_path = app.instance_path
        if not os.path.exists(instance_path):
            print(f"Creating instance directory: {instance_path}")
            os.makedirs(instance_path, exist_ok=True)
        
        # Print database path for debugging
        db_path = os.path.join(instance_path, 'billing.db')
        print(f"Database path: {db_path}")
        
        # Create database tables
        db.create_all()
        print("Database tables created successfully")
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='jewel_admin').first()
        if not admin:
            admin = User(
                username='jewel_admin',
                email='pramodalmel@gmail.com',
                password=generate_password_hash('JewelBox@2024'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists")
            
        # Verify database is writable
        test_user = User(username='test_user', password=generate_password_hash('test123'), role='user')
        db.session.add(test_user)
        db.session.commit()
        print("Test user created successfully")
    except Exception as e:
        print(f"Error during initialization: {str(e)}")
        db.session.rollback()

if __name__ == "__main__":
    app.run(debug=True)
    
    try:
        # Initialize database and create admin user
        init_db()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        
    # Run the application
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))