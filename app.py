from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    calculations = db.relationship('Calculation', backref='user', lazy=True)

class Calculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    num1 = db.Column(db.Float)
    num2 = db.Column(db.Float)
    result = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    print("Home page accessed") 
    return render_template('home.html')

@app.route('/multiply', methods=['GET', 'POST'])
@login_required
def multiply():
    if request.method == 'POST':
        try:
            num1 = float(request.form['num1'])
            num2 = float(request.form['num2'])
            result = num1 * num2
            
            # Save calculation to history
            calc = Calculation(num1=num1, num2=num2, result=result, user_id=current_user.id)
            db.session.add(calc)
            db.session.commit()
            
            return render_template('multiply.html', result=result, history=current_user.calculations)
        except ValueError:
            flash('Please enter valid numbers')
    return render_template('multiply.html', history=current_user.calculations)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("login route accessed")  # Check terminal for this
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('multiply'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    print("Signup route accessed")  # Check terminal for this
    if request.method == 'POST':
        print("POST request received")
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        new_user = User(
            username=username,
            password=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('multiply'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)