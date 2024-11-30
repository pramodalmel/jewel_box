import plotly.graph_objects as go
from flask import Flask, render_template, request

app = Flask(__name__)

# Sample data for the pie chart and scatter plot
billing_data_list = [
    {'item': 'Ring', 'price': 1200, 'date': '2024-11-01'},
    {'item': 'Necklace', 'price': 1800, 'date': '2024-11-02'},
    {'item': 'Earrings', 'price': 1500, 'date': '2024-11-03'},
    {'item': 'Ring', 'price': 800, 'date': '2024-11-04'},
    {'item': 'Necklace', 'price': 2500, 'date': '2024-11-05'}
]

@app.route("/")
def home():
    # Data for pie chart (Items and Prices)
    items = ["Ring", "Necklace", "Earrings"]
    total_prices = [0, 0, 0]

    # Accumulate the total prices for each item
    for data in billing_data_list:
        if data['item'] == 'Ring':
            total_prices[0] += data['price']
        elif data['item'] == 'Necklace':
            total_prices[1] += data['price']
        elif data['item'] == 'Earrings':
            total_prices[2] += data['price']

    # Pie Chart for Item Prices
    pie_chart_fig = go.Figure(data=[go.Pie(labels=items, values=total_prices, hole=0.3)])
    pie_chart_fig.update_traces(textinfo='percent+label', marker=dict(colors=['#FF6347', '#4CAF50', '#2196F3']))
    pie_chart_html = pie_chart_fig.to_html(full_html=False)

    # Data for Scatter Plot (Date vs Price)
    dates = [data['date'] for data in billing_data_list]
    prices = [data['price'] for data in billing_data_list]

    # Scatter Plot for Date vs Price
    scatter_fig = go.Figure(data=[go.Scatter(x=dates, y=prices, mode='markers', marker=dict(size=10, color='rgba(255, 99, 132, 0.6)'))])
    scatter_fig.update_layout(title='Date vs Price', xaxis_title='Date', yaxis_title='Price')
    scatter_html = scatter_fig.to_html(full_html=False)

    return render_template("index.html", pie_chart=pie_chart_html, scatter_plot=scatter_html)

@app.route("/billing", methods=["GET", "POST"])
def billing():
    if request.method == "POST":
        # Fetching form data
        name = request.form["name"]
        contact = request.form["contact"]
        address = request.form["address"]
        date = request.form["date"]
        item = request.form["item"]
        quantity = request.form["quantity"]
        price = request.form["price"]
        discount = request.form["discount"]
        tax = request.form["tax"]

        # Calculate the total price
        price = float(price)
        discount = float(discount)
        tax = float(tax)

        discount_amount = price * (discount / 100)
        tax_amount = price * (tax / 100)
        total_price = price - discount_amount + tax_amount

        billing_data = {
            "name": name,
            "contact": contact,
            "address": address,
            "date": date,
            "item": item,
            "quantity": quantity,
            "price": price,
            "discount": discount,
            "tax": tax,
            "total_price": total_price
        }

        # Add the new billing data to the list (this will be used for the pie chart)
        billing_data_list.append({
            "item": item,
            "price": total_price,
            "date": date
        })

        return render_template("index.html", billing_data=billing_data, pie_chart=None, scatter_plot=None)

    return render_template("billing_form.html")

if __name__ == "__main__":
    app.run(debug=True)