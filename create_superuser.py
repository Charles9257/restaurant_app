from models import db, User
from werkzeug.security import generate_password_hash
from app import app

# --- CONFIGURE ---
username = "admin"
email = "ogbonnacharles684@gmail.com"
password = "9257@Charles"  # Change this after first login!

with app.app_context():
    existing = User.query.filter_by(email=email).first()
    hashed = generate_password_hash(password)
    if existing:
        print(f"User with email {email} already exists.")
        existing.is_admin = True
        existing.password = hashed  # Always reset to a valid hash
        db.session.commit()
        print("User promoted to admin and password reset.")
    else:
        user = User(username=username, email=email, password=hashed, is_admin=True)
        db.session.add(user)
        db.session.commit()
        print(f"Superuser {username} created.")
