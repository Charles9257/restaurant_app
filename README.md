# Restaurant App

A modern restaurant management web application built with Flask, SQLAlchemy, Bootstrap, and Chart.js.

## Features
- User registration and login
- Admin dashboard with sidebar navigation
- User management: add, update, promote, demote, delete users
- Order management: view recent orders, order details
- Chart visualizations: sales by day, top customers, item popularity
- Settings: update admin email, password, and site name
- AJAX integration for admin actions and settings

## Technologies
- Python 3, Flask, SQLAlchemy, Flask-Login, Flask-WTF, Flask-Migrate
- Bootstrap 5, Bootstrap Icons, Chart.js
- SQLite database

## Getting Started
1. Clone the repository:
	```bash
	git clone https://github.com/Charles9257/restaurant_app.git
	cd restaurant_app
	```
2. Install dependencies:
	```bash
	pip install -r requirements.txt
	```
3. Run database migrations:
	```bash
	flask db init
	flask db migrate
	flask db upgrade
	```
4. Create a superuser (admin):
	```bash
	python create_superuser.py
	```
5. Start the app:
	```bash
	python app.py
	```
6. Access the app at [http://localhost:5000](http://localhost:5000)

## Folder Structure
- `app.py` - Main Flask application
- `models.py` - Database models
- `templates/` - HTML templates (Jinja2)
- `static/` - Static files (CSS, JS, images)
- `requirements.txt` - Python dependencies
- `README.md` - Project documentation

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
MIT