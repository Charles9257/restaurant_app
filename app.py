
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from models import db, User, Order
from forms import LoginForm, RegisterForm, OrderForm, AdminLoginForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter, defaultdict
from flask_migrate import Migrate
from datetime import datetime
from sqlalchemy import func

app = Flask(__name__)
app.config.from_object('config')
db.init_app(app)

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
     
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/menu")
def menu():
    return render_template("menu.html")

@app.route("/place")
def place():
    return render_template("place.html")

@app.route("/order", methods=["GET", "POST"])
@login_required
def order():
    return render_template("order.html")

@app.route("/place_order", methods=["POST"])
@login_required
def place_order():
    if request.is_json:
        data = request.get_json()
        # If cart is present, handle full checkout
        if 'cart' in data:
            cart = data.get('cart', {})
            address = data.get('address', '')
            phone = data.get('phone', '')
            postcode = data.get('postcode', '')
            vat = float(data.get('vat', 0))
            shipping = float(data.get('shipping', 0))
            grand_total = float(data.get('grandTotal', 0))
            if not address or not phone or not postcode or not cart:
                return jsonify({'message': 'Please fill all checkout fields and add items to cart.', 'status': 'danger'}), 400
            # Save order
            order = Order(user_id=current_user.id, total=grand_total, items=cart, status='Pending', address=address, phone=phone, postcode=postcode)
            db.session.add(order)
            db.session.commit()
            # You can extend Order model to save address, phone, postcode if needed
            return jsonify({'message': 'Order placed successfully! We will contact you soon.', 'status': 'success'}), 200
        # Fallback: single cuisine order (legacy)
        cuisine = data.get('cuisine')
        prices = {
            'Jollof Rice': 10, 'Egusi Soup': 12, 'Pounded Yam': 8,
            'Pad Thai': 11, 'Green Curry': 13, 'Tom Yum Soup': 9,
            'Burger': 7, 'Fries': 4, 'BBQ Ribs': 15,
            'Pasta': 9, 'Pizza': 10, 'Risotto': 12,
            'Biryani': 10, 'Butter Chicken': 13, 'Naan': 3
        }
        available_cuisines = [
            'Jollof Rice', 'Pounded Yam', 'Pad Thai', 'Green Curry',
            'Burger', 'Fries', 'Pasta', 'Pizza', 'Biryani', 'Butter Chicken', 'Naan'
        ]
        if cuisine not in prices:
            return jsonify({'message': 'Invalid cuisine selected.', 'status': 'danger'}), 400
        if cuisine not in available_cuisines:
            return jsonify({'message': f'{cuisine} is not available.', 'status': 'danger'}), 400
        order = Order(user_id=current_user.id, total=prices[cuisine], items={cuisine: 1})
        db.session.add(order)
        db.session.commit()
        return jsonify({'message': f'Order for {cuisine} placed successfully!', 'status': 'success'}), 200
    return jsonify({'message': 'Invalid request.', 'status': 'danger'}), 400

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        # Check for duplicate email or username
        if User.query.filter_by(email=form.email.data).first() or User.query.filter_by(username=form.username.data).first():
            flash("Email or username already exists.", "danger")
            return render_template("register.html", form=form)
        if not form.password.data:
            flash("Password is required.", "danger")
            return render_template("register.html", form=form)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        print("Already authenticated, redirecting to order.")
        return redirect(url_for('order'))
    form = LoginForm()
    print("Form submitted:", form.is_submitted())
    print("Form validated:", form.validate_on_submit())
    if form.is_submitted():
        print("Form data:", form.data)
    if form.validate_on_submit():
        print("Email:", form.email.data)
        user = User.query.filter_by(email=form.email.data).first()
        print("User found:", user is not None)
        if user:
            print("Password check:", check_password_hash(user.password, form.password.data))
        if user and check_password_hash(user.password, form.password.data):
            print("Login successful, redirecting to order.")
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('order'))
        print("Invalid credentials.")
        flash("Invalid credentials. Please check your email and password.", "danger")
    elif form.is_submitted():
        print("Form did not validate. Errors:", form.errors)
        flash("Form validation failed. Please fill all fields correctly.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# app.py (add these imports at the top if missing)
from collections import Counter, defaultdict
from datetime import datetime
from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import func
from models import db, User, Order

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.is_admin and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        flash("Invalid admin credentials or not an admin.", "danger")
    return render_template("admin_login.html", form=form)


# --- Save Settings Route ---
@app.route('/admin/save_settings', methods=['POST'])
@login_required
def save_settings():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    data = request.get_json()
    site_name = data.get('siteName')
    admin_email = data.get('adminEmail')
    change_password = data.get('changePassword')
    user = User.query.get(current_user.id)
    if admin_email:
        user.email = admin_email
    if change_password:
        user.password = generate_password_hash(change_password)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Settings saved successfully.'})

# --- ADMIN USER ACTIONS ---
@app.route('/admin/user/<int:user_id>/promote', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if user:
        user.is_admin = True
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User promoted to admin.'})
    return jsonify({'status': 'error', 'message': 'User not found.'}), 404

@app.route('/admin/user/<int:user_id>/demote', methods=['POST'])
@login_required
def demote_user(user_id):
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if user:
        user.is_admin = False
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User demoted from admin.'})
    return jsonify({'status': 'error', 'message': 'User not found.'}), 404

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User deleted.'})
    return jsonify({'status': 'error', 'message': 'User not found.'}), 404


# ----------------- ROUTES -----------------
@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    orders = Order.query.order_by(Order.date.desc()).all()
    total_orders = len(orders)
    total_sales = sum(order.total for order in orders)
    item_counts = Counter()
    for order in orders:
        for item, detail in order.items.items():
            item_counts[item] += detail.get('qty', 1) if isinstance(detail, dict) else detail

    # --- User Management ---
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_dashboard.html", orders=orders, total_orders=total_orders, total_sales=total_sales, item_counts=item_counts, users=users)

# --- Add User Route ---
@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    if not username or not email or not password:
        return jsonify({'status': 'error', 'message': 'All fields are required.'}), 400
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({'status': 'error', 'message': 'Email or username already exists.'}), 400
    hashed_password = generate_password_hash(password)
    user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
    db.session.add(user)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'User added successfully.'})

# --- Update User Route ---
@app.route('/admin/update_user', methods=['POST'])
@login_required
def update_user():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    data = request.get_json()
    user_id = data.get('id')
    username = data.get('username')
    email = data.get('email')
    is_admin = data.get('is_admin', False)
    password = data.get('password')
    user = User.query.get(user_id)
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    if username:
        user.username = username
    if email:
        user.email = email
    user.is_admin = is_admin
    if password:
        user.password = generate_password_hash(password)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'User updated successfully.'})

@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    orders = Order.query.order_by(Order.date.asc()).all()

    # --- KPIs ---
    total_orders = len(orders)
    total_sales = float(sum(o.total for o in orders)) if orders else 0.0
    aov = (total_sales / total_orders) if total_orders else 0.0

    # repeat customer rate
    orders_per_user = defaultdict(int)
    for o in orders:
        orders_per_user[o.user_id] += 1
    repeat_customers = sum(1 for _, c in orders_per_user.items() if c > 1)
    total_customers = len(orders_per_user)
    repeat_rate = (repeat_customers / total_customers) * 100 if total_customers else 0.0

    # --- Sales per day and per ISO week ---
    sales_per_day = defaultdict(float)
    sales_per_week = defaultdict(float)
    weekday_counts = defaultdict(int)  # 0=Mon ... 6=Sun
    for o in orders:
        d = o.date.date()
        sales_per_day[d.strftime("%Y-%m-%d")] += float(o.total)
        iso_year, iso_week, _ = o.date.isocalendar()
        wk_key = f"{iso_year}-W{iso_week:02d}"
        sales_per_week[wk_key] += float(o.total)
        weekday_counts[o.date.weekday()] += 1

    # Sort by date/week
    sales_dates = sorted(sales_per_day.keys())
    sales_amounts = [round(sales_per_day[d], 2) for d in sales_dates]
    week_labels = sorted(sales_per_week.keys())
    week_amounts = [round(sales_per_week[w], 2) for w in week_labels]
    weekday_labels = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    weekday_values = [weekday_counts.get(i, 0) for i in range(7)]

    # --- Item popularity (top 10) ---
    item_counts = Counter()
    for o in orders:
        if isinstance(o.items, dict):
            for item, qty in o.items.items():
                item_counts[item] += int(qty)
    top_items = item_counts.most_common(10)
    item_names = [name for name, _ in top_items]
    item_qtys = [qty for _, qty in top_items]

    # --- Revenue per customer (top 10) ---
    revenue_per_user = defaultdict(float)
    for o in orders:
        revenue_per_user[o.user_id] += float(o.total)
    # join usernames
    user_map = {u.id: u.username for u in User.query.with_entities(User.id, User.username).all()}
    top_customers = sorted(revenue_per_user.items(), key=lambda x: x[1], reverse=True)[:10]
    customer_names = [user_map.get(uid, f"User {uid}") for uid, _ in top_customers]
    customer_revenue = [round(amount, 2) for _, amount in top_customers]

    return render_template(
        "dashboard.html",
        # KPIs
        total_orders=total_orders,
        total_sales=round(total_sales, 2),
        aov=round(aov, 2),
        repeat_rate=round(repeat_rate, 1),

        # charts
        sales_dates=sales_dates,
        sales_amounts=sales_amounts,
        week_labels=week_labels,
        week_amounts=week_amounts,
        item_names=item_names,
        item_qtys=item_qtys,
        customer_names=customer_names,
        customer_revenue=customer_revenue,
        weekday_labels=weekday_labels,
        weekday_values=weekday_values
    )




# Run Flask
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
