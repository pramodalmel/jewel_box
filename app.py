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
db = SQLAlchemy(app)

# Database models for Billing and User
class Billing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.String(50), nullable=False)
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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Helper function to get the time range for filtering data
def get_time_range(time_period):
    today = datetime.today()
    if time_period == "daily":
        start_date = today.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "weekly":
        start_date = today - timedelta(days=today.weekday())  # Start of the week
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "monthly":
        start_date = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif time_period == "yearly":
        start_date = today.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return start_date.strftime("%Y-%m-%d")

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/", methods=["GET", "POST"])
def home():
    # Ensure user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    time_period = request.args.get("time_period", "daily")
    start_date = get_time_range(time_period)
    
    # Get billing data based on time period
    billing_data = Billing.query.filter(Billing.date >= start_date).all()
    items = {}
    for bill in billing_data:
        if bill.item not in items:
            items[bill.item] = bill.total_price
        else:
            items[bill.item] += bill.total_price

    # Pie chart for sales distribution
    labels = list(items.keys())
    values = list(items.values())
    pie_chart_fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    pie_chart_html = pie_chart_fig.to_html(full_html=False)

    # Scatter plot for date vs total price
    dates = [datetime.strptime(bill.date, "%Y-%m-%d").date() for bill in billing_data]
    total_prices = [bill.total_price for bill in billing_data]
    scatter_fig = go.Figure(
        data=[go.Scatter(
                x=dates, 
                y=total_prices, 
                mode='markers', 
                marker=dict(size=10, color='rgba(255, 99, 132, 0.6)')
            )
        ]
    )
    scatter_fig.update_layout(
        title_text="Date vs Total Price Scatter Plot", 
        title_x=0.5,
        xaxis_title="Date",
        yaxis_title="Amount",
        xaxis=dict(type="category")  # Treat dates as categories
    )
    scatter_html = scatter_fig.to_html(full_html=False)

    return render_template("index.html", pie_chart=pie_chart_html, scatter_plot=scatter_html)

@app.route("/billing", methods=["GET", "POST"])
def billing():
    if request.method == "POST":
        name = request.form["name"]
        contact = request.form["contact"]
        address = request.form["address"]
        date = request.form["date"]
        items = request.form.getlist("item")
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
                name=name, contact=contact, address=address, date=date,
                item=items[i], quantity=quantities[i], price=prices[i],
                discount=discounts[i], tax=taxes[i], total_price=total_price
            )
            db.session.add(new_billing)

        db.session.commit()

        return redirect(f"/bill/{bill_id}")
    return render_template("billing_form.html")

@app.route("/bill_summary/<transaction_id>")
def bill_summary(transaction_id):
    billing_entries = Billing.query.filter_by(transaction_id=transaction_id).all()
    total_price = request.args.get("total", 0)
    return render_template("bill_summary.html", billing_entries=billing_entries, total_price=total_price)

@app.route("/bill/<string:bill_id>")
def bill(bill_id):
    billing_data = Billing.query.filter_by(bill_id=bill_id).all()
    total_amount = sum(item.total_price for item in billing_data)
    return render_template("bill.html", billing_data=billing_data, total_amount=total_amount)

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials, please try again.", 'error')
    return render_template("login.html")

# Signup Route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!", 'error')
            return redirect(url_for('signup'))
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please login.", 'success')
        return redirect(url_for('login'))
    
    return render_template("signup.html")

# Logout Route
@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))