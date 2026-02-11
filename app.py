from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_mail import Mail, Message
from datetime import datetime
import random
from sqlalchemy import or_

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cars.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Gmail SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'YOUR_GMAIL@gmail.com'
app.config['MAIL_PASSWORD'] = 'YOUR_APP_PASSWORD'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# ---------------- LOGIN MANAGER ---------------- #
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- MODELS ---------------- #
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(200), nullable=False)


class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    otp = db.Column(db.String(6))
    timestamp = db.Column(db.DateTime)


class CarTodo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_trip_id = db.Column(db.Integer, nullable=False)
    car_number = db.Column(db.String(20), nullable=False)
    start_point = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    car_for = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- FORGOT PASSWORD ---------------- #
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form['identifier']

        user = User.query.filter(or_(User.email == identifier, User.phone == identifier)).first()

        if not user:
            flash("No account found!", "danger")
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))

        reset_entry = PasswordResetOTP(
            email=user.email,
            otp=otp,
            timestamp=datetime.now()
        )
        db.session.add(reset_entry)
        db.session.commit()

        msg = Message(
            "Your OTP Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)

        return redirect(url_for('verify_otp', email=user.email))

    return render_template('forgot_password.html')

# ---------------- VERIFY OTP ---------------- #
@app.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        otp_entered = request.form['otp']

        otp_record = PasswordResetOTP.query.filter_by(email=email) \
            .order_by(PasswordResetOTP.id.desc()).first()

        if not otp_record or otp_record.otp != otp_entered:
            flash("Invalid OTP!", "danger")
            return redirect(url_for('verify_otp', email=email))

        return redirect(url_for('reset_password', email=email))

    return render_template('verify_otp.html')

# ---------------- RESET PASSWORD ---------------- #
@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form['password']

        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        return "Password successfully updated!"

    return render_template('reset_password.html')

# ---------------- HOME ---------------- #
@app.route('/')
@login_required
def index():
    cars = CarTodo.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', cars=cars)
@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html')
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')



# ---------------- ADD TRIP ---------------- #
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        if request.form.get('details_confirm') != 'on':
            flash("Confirm details first!", "danger")
            return redirect(url_for('add'))

        last_trip = CarTodo.query.filter_by(user_id=current_user.id) \
            .order_by(CarTodo.user_trip_id.desc()).first()

        next_trip_number = 1 if not last_trip else last_trip.user_trip_id + 1

        new_car = CarTodo(
            user_trip_id=next_trip_number,
            car_number=request.form['car_number'],
            start_point=request.form['start_point'],
            destination=request.form['destination'],
            date=request.form['date'],
            car_for=request.form['car_for'],
            amount=float(request.form.get('amount', 0)),
            user_id=current_user.id
        )

        db.session.add(new_car)
        db.session.commit()

        return redirect(url_for('welcome'))

    return render_template('add.html')
# ---------------- EDIT TRIP ---------------- #
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    car = CarTodo.query.get_or_404(id)

    # Make sure user can only edit their own data
    if car.user_id != current_user.id:
        return "Not allowed", 403

    if request.method == 'POST':

        if request.form.get('details_confirm') != 'on':
            flash("Please confirm details before updating!", "danger")
            return redirect(url_for('edit', id=id))

        # Update fields
        car.car_number = request.form['car_number']
        car.start_point = request.form['start_point']
        car.destination = request.form['destination']
        car.date = request.form['date']
        car.car_for = request.form['car_for']
        car.amount = float(request.form.get('amount', 0))

        db.session.commit()
        flash("Trip updated successfully!", "success")
        return redirect(url_for('edit', id=id))

    return render_template('edit.html', car=car)


# ---------------- DELETE TRIP ---------------- #
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    car = CarTodo.query.get_or_404(id)

    if car.user_id != current_user.id:
        return "Not allowed", 403

    db.session.delete(car)
    db.session.commit()

    return redirect(url_for('index'))

# ---------------- REGISTER ---------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = bcrypt.generate_password_hash(
            request.form['password']
        ).decode('utf-8')

        user = User(
            username=request.form['username'],
            email=request.form['email'],
            phone=request.form['phone'],
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

# ---------------- LOGIN ---------------- #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        identifier = request.form['identifier']  # can be username or email or phone
        password = request.form['password']

        # Allow login with username OR email OR phone
        user = User.query.filter(
            or_(
                User.username == identifier,
                User.email == identifier,
                User.phone == identifier
            )
        ).first()

        if not user:
            flash("Account does not exist!", "danger")
            return redirect(url_for('login'))

        if not bcrypt.check_password_hash(user.password, password):
            flash("Incorrect password!", "danger")
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('welcome'))

    return render_template('login.html')


# ---------------- LOGOUT ---------------- #
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------- RUN APP ---------------- #
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)

