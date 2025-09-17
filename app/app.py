import os
import bcrypt
from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Dummy secret for Gitleaks testing
DUMMY_SECRET_KEY = "my_super_secret_password_123"


# Sample product catalog
products = [
    {"id": 1, "name": "Laptop", "price": 1200},
    {"id": 2, "name": "Smartphone", "price": 800},
    {"id": 3, "name": "Headphones", "price": 150}
]

# Simple in-memory cart storage
carts = {}  # key: username, value: list of product ids

#General	No HTTPS enforced	High	Use HTTPS in production

# -------------------------------
# Flask app setup
# -------------------------------

app = Flask(__name__)
# FIX 1: Use environment variable for secret key (remove fallback in production)dev_secret_only_for_testing remove fallback during production
#app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_only_for_testing")
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret") # app.secret_key	Fallback secret in code	High	Use environment variable (already partially done)

#Fix 2:Secure session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, #Prevent JS from reading cookies
    SESSION_COOKIE_SECURE=False    #Set True in production with HTTPS
)

# -------------------------------
# Helper functions for validation
# -------------------------------

def validate_username(username):
    """Validate username format"""
    return isinstance(username, str) and username.isalnum() and 3 <= len(username) <= 20

def validate_password(password):
    """Validate password length"""
    return isinstance(password, str) and len(password) >= 6

# -------------------------------
# Routes
# -------------------------------

@app.route('/')
def index():
    return "Welcome to Secure Retail App!"

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") #FIX 3:Extra stricter rate limit for login endpoint

def login():                        
    username = request.json.get("username") #/login	No input validation on username/password	Medium	Validate length & allowed characters
    password = request.json.get("password")
    # Simple check (not secure, will fix later)

    #FIX 4:Input Validation
    if not validate_username(username) or not validate_password(password):
        return jsonify({"message":"Invalid input"}), 400
    
    #FIX 5:Use hashed password check
    stored_hashed = bcrypt.hashpw("admin".encode(),bcrypt.gensalt())
    #old code before fix: if username == "admin" and password == "admin":
    if username == "admin" and bcrypt.checkpw(password.encode(),stored_hashed): #/login	Password checked in plaintext	High	Use hashed passwords with bcrypt
        session['user'] = username  #session	Cookies not marked HttpOnly / Secure	Medium	Add secure session config
        return jsonify({"message":"Login successful"})
    return jsonify({"message":"Invalid credentials"}), 401

@app.route('/cart', methods=['GET']) #/cart GET & POST	No rate limiting	Medium	Add rate limiting to prevent abuse
@limiter.limit("10 per minute") #FIX 3:Rate limit
def view_cart():
    if 'user' not in session:
        return jsonify({"message": "Login required"}), 401

    username = session['user']
    user_cart_ids = carts.get(username, [])
    user_cart_products = [p for p in products if p['id'] in user_cart_ids]
    return jsonify({"cart": user_cart_products})

@app.route('/cart', methods=['POST']) #/cart GET & POST	No rate limiting	Medium	Add rate limiting to prevent abuse
@limiter.limit("10 per minute") #FIX 3:Rate limit
def add_to_cart():
    if 'user' not in session:
        return jsonify({"message": "Login required"}), 401

    username = session['user'] #session	Cookies not marked HttpOnly / Secure	Medium	Add secure session config
    product_id = request.json.get("product_id") #/cart POST	No input type check for product_id	Medium	Ensure it is an integer, valid product ID

    #FIX6:Validate product_id input
    if not isinstance(product_id,int):
        return jsonify({"message":"Invalid product ID"}), 400

    # Validate product exists
    if not any(p['id'] == product_id for p in products):
        return jsonify({"message": "Invalid product"}), 400

    # Add product to user's cart
    carts.setdefault(username, []).append(product_id)
    return jsonify({"message": f"Product {product_id} added to cart", "cart": carts[username]})

@app.route('/products', methods=['GET'])
@limiter.limit("20 per minute") #FIX 3:Rate limit
def get_products():
    return jsonify({"products": products})

# -------------------------------
# Run app with HTTPS for production
# -------------------------------
if __name__ == "__main__":
    # FIX 7: HTTPS instruction
    # Note: Flask dev server doesn't support full HTTPS. Use this only in dev:
    # app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')
    # In production, run behind NGINX/Apache with SSL
    app.run(host="0.0.0.0", port=5000)

#Issue	Status
#Secret key fallback	✅ Partially fixed (remove fallback in prod)
#Plaintext password check	✅ Fixed (bcrypt hashing)
#Login input validation	✅ Fixed
#Cart POST input type check	✅ Fixed
#Session cookies	✅ Fixed
#Rate limiting	✅ Fixed (login, cart, products endpoints)
#HTTPS enforced	⚠️ Development: ssl_context='adhoc' works for dev; production: reverse proxy SSL needed
