from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import plotly.graph_objects as go
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///billing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)  # For session management
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Session lasts 1 day
db = SQLAlchemy(app)

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
    user = db.relationship('User', backref=db.backref('bills', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Helper functions
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
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('admin123')
        admin = User(username='admin', password=hashed_password)
        db.session.add(admin)
        db.session.commit()

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

# Routes
@app.route("/about")
def about():
    return render_template('about.html')
    
@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/", methods=["GET", "POST"])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    time_period = request.args.get("time_period", "daily")
    start_date = get_time_range(time_period)
    
    # Get billing data for the selected time period and current user
    billing_data = Billing.query.filter(
        Billing.date >= start_date,
        Billing.user_id == session['user_id']
    ).all()
    
    # Calculate revenue metrics
    today = datetime.today().strftime("%Y-%m-%d")
    daily_revenue = sum(bill.total_price for bill in billing_data if bill.date == today)
    daily_bills = len([bill for bill in billing_data if bill.date == today])
    
    # Calculate monthly revenue (from start of current month)
    monthly_start = datetime.today().replace(day=1).strftime("%Y-%m-%d")
    monthly_revenue = sum(bill.total_price for bill in Billing.query.filter(
        Billing.date >= monthly_start,
        Billing.user_id == session['user_id']
    ).all())

    # Group items by type for pie chart
    items = {}
    for bill in billing_data:
        if bill.item not in items:
            items[bill.item] = bill.total_price
        else:
            items[bill.item] += bill.total_price

    # Pie chart
    labels = list(items.keys())
    values = list(items.values())
    pie_chart_fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    pie_chart_fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        margin=dict(t=80, b=40, l=40, r=40),
        height=400,
        width=500,
        title=dict(
            text="Sales Distribution",
            x=0.5,
            y=0.95,
            xanchor="center",
            yanchor="top"
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
    )
    pie_chart_html = pie_chart_fig.to_html(full_html=False, config={'displayModeBar': False})

    # Scatter plot for sales trend
    dates = [datetime.strptime(bill.date, "%Y-%m-%d").date() for bill in billing_data]
    total_prices = [bill.total_price for bill in billing_data]
    scatter_fig = go.Figure(
        data=[go.Scatter(
                x=dates, 
                y=total_prices, 
                mode='markers+lines', 
                marker=dict(size=10, color='rgba(255, 99, 132, 0.6)'),
                line=dict(color='rgba(255, 99, 132, 0.6)')
            )
        ]
    )
    scatter_fig.update_layout(
        title_text="Sales Trend", 
        title_x=0.5,
        xaxis_title="Date",
        yaxis_title="Amount (₹)",
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

@app.route("/billing", methods=["GET", "POST"])
def billing():
    if 'username' not in session:
        return redirect(url_for('login'))

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

        bill_id = f"bill_{datetime.now().strftime('%Y%m%d%H%M%S')}"
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
        flash("Bill created successfully!", "success")
        return redirect(f"/bill/{bill_id}")
    
    return render_template("billing_form.html")

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
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['user_id'] = user.id
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password", "error")
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")
        
        if password != confirm_password:
            flash("Passwords don't match!", "error")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created! Please login.", "success")
            return redirect(url_for('login'))
    
    return render_template("signup.html")

@app.route("/logout")
def logout():
    if 'user_id' in session:
        # Clear user's bills
        Billing.query.filter_by(user_id=session['user_id']).delete()
        db.session.commit()
    session.pop('username', None)
    session.pop('user_id', None)
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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))