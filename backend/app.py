'''import secrets  
from flask import Flask, render_template, request, redirect, url_for, flash  
from flask_sqlalchemy import SQLAlchemy  
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user  

app = Flask(__name__)  

# Generate a secure random secret key  
app.config['SECRET_KEY'] = secrets.token_hex(16)  

# MySQL Database Configuration  
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:suga@localhost/mental_health_prj'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  

db = SQLAlchemy(app)  
login_manager = LoginManager()  
login_manager.init_app(app)  
login_manager.login_view = 'login'  

# User Model  
class User(UserMixin, db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(150), unique=True, nullable=False)  
    password = db.Column(db.String(150), nullable=False)  # Store hashed passwords later  

@login_manager.user_loader  
def load_user(user_id):  
    return User.query.get(int(user_id))  

# Home Route  
@app.route('/')  
def home():  
    return render_template('index.html')  

# Login Route  
@app.route('/login', methods=['GET', 'POST'])  
def login():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  
        user = User.query.filter_by(username=username).first()  

        if user and user.password == password:  # Replace with hashed password check later  
            login_user(user)  
            return redirect(url_for('profile', username=user.username))  
        else:  
            flash('Invalid username or password', 'error')  

    return render_template('login.html')  

# Profile Route  
@app.route('/profile/<username>')  
@login_required  
def profile(username):  
    return render_template('profile.html', username=username)  

# Logout Route  
@app.route('/logout')  
@login_required  
def logout():  
    logout_user()  
    return redirect(url_for('login'))  

if __name__ == '__main__':  
    with app.app_context():  
        db.create_all()  
    app.run(debug=True)  
'''
'''import secrets  
from flask import Flask, render_template, request, redirect, url_for, flash  
from flask_sqlalchemy import SQLAlchemy  
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user  
from werkzeug.security import generate_password_hash, check_password_hash  

app = Flask(__name__)  

# Generate a secure random secret key  
app.config['SECRET_KEY'] = secrets.token_hex(16)  

# MySQL Database Configuration  
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:suga@localhost/mental_health_prj'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  

db = SQLAlchemy(app)  
login_manager = LoginManager()  
login_manager.init_app(app)  
login_manager.login_view = 'login'  

# User Model  
class User(UserMixin, db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(150), unique=True, nullable=False)  
    password = db.Column(db.String(150), nullable=False)  # Store hashed passwords  

@login_manager.user_loader  
def load_user(user_id):  
    return User.query.get(int(user_id))  

# Home Route  
@app.route('/')  
def home():  
    return render_template('index.html')  

# Register Route (Fixed - No duplicate definition)  
@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists! Choose another.', 'error')
            return redirect(url_for('register'))

        # Hash password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create new user and store in database
        new_user = User(username=username, password=hashed_password)  
        db.session.add(new_user)  
        db.session.commit()  

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))  

    return render_template('register.html')  

# Login Route  
@app.route('/login', methods=['GET', 'POST'])  
def login():  
    if request.method == 'POST':  
        username = request.form['username']  
        password = request.form['password']  
        user = User.query.filter_by(username=username).first()  

        if user and check_password_hash(user.password, password):  # Secure password check  
            login_user(user)  
            flash('Login successful!', 'success')
            return redirect(url_for('home'))  # Redirect to home or dashboard
        else:  
            flash('Invalid username or password', 'error')  

    return render_template('')  

# Profile Route  
@app.route('/profile/<username>')  
@login_required  
def profile(username):  
    return render_template('profile.html', username=username)  

# Logout Route  
@app.route('/logout')  
@login_required  
def logout():  
    logout_user()  
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))  

if __name__ == '__main__':  
    with app.app_context():  
        db.create_all()  # Ensure database tables are created
    app.run(debug=True)  
    '''


'''
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, send
from datetime import datetime
import re  # For input validation

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:suga@localhost/mental_health_prj'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

socketio = SocketIO(app)  # Initialize SocketIO for real-time chat

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Message Model for storing chat messages
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Input validation
        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Invalid username. Use only letters, numbers, dots, hyphens, and underscores.', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists! Choose another.', 'error')
            return redirect(url_for('register'))

        # Hash password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['username'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()  # Get other users
    return render_template('dashboard.html', users=users)

# Chat Route
@app.route('/chat/<username>')
@login_required
def chat(username):
    recipient = User.query.filter_by(username=username).first()
    if not recipient:
        flash('User does not exist.', 'error')
        return redirect(url_for('dashboard'))
    
    # Fetch previous messages between users
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    return render_template('community_sel.html', recipient=recipient, messages=messages)

# WebSocket for real-time messaging
@socketio.on('send_message')
def handle_send_message(data):
    sender = current_user.username
    receiver = data['receiver']
    message = data['message'].strip()

    if message:  # Check if message is not empty
        # Save message to database
        receiver_user = User.query.filter_by(username=receiver).first()
        new_message = Message(sender_id=current_user.id, receiver_id=receiver_user.id, message=message)
        db.session.add(new_message)
        db.session.commit()

        send({'sender': sender, 'message': message}, room=receiver)

@socketio.on('join')
def handle_join(data):
    join_room(data['room'])

@socketio.on('leave')
def handle_leave(data):
    leave_room(data['room'])

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database tables are created
    socketio.run(app, debug=True)


'''



















'''import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, send
from datetime import datetime
from flask_cors import CORS  # For CORS handling
import requests  # For proxy routes
import re  # For input validation

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:suga@localhost/mental_health_prj'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
CORS(app)  # Enable CORS for all routes

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    community = db.Column(db.String(50), nullable=True)  # New: User community

# Message Model for storing chat messages
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        community = request.form['community']  # New: Get community

        # Input validation
        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Invalid username.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, community=community)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')'''

# Register Route
'''@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        community = request.form['community']
        bio = request.form.get('bio', '').strip()  # New: Get bio from form
        interests = request.form.get('interests', '').strip()  # New: Get interests from form

        # Input validation
        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Invalid username.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, community=community)
        db.session.add(new_user)
        db.session.commit()

        # Create a profile for the new user
        new_profile = UserProfile(user_id=new_user.id, community=community, bio=bio, interests=interests)
        db.session.add(new_profile)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('dashboard.html', users=users)

# Matchmaking based on community
@app.route('/find_match')
@login_required
def find_match():
    matched_users = User.query.filter(User.community == current_user.community, User.id != current_user.id).all()
    return render_template('matches.html', matched_users=matched_users)

# Chat Route
@app.route('/chat/<username>')
@login_required
def chat(username):
    recipient = User.query.filter_by(username=username).first()
    if not recipient:
        flash('User does not exist.', 'error')
        return redirect(url_for('dashboard'))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    return render_template('community_sel.html', recipient=recipient, messages=messages)

# WebSocket for real-time messaging
@socketio.on('send_message')
def handle_send_message(data):
    sender = current_user.username
    receiver = data['receiver']
    message = data['message'].strip()

    if message:
        receiver_user = User.query.filter_by(username=receiver).first()
        new_message = Message(sender_id=current_user.id, receiver_id=receiver_user.id, message=message)
        db.session.add(new_message)
        db.session.commit()

        send({'sender': sender, 'message': message}, room=receiver)

# CORS Proxy for external APIs
@app.route('/proxy/quote')
def proxy_quote():
    response = requests.get('https://api.quotable.io/random')
    return jsonify(response.json())

@app.route('/proxy/image')
def proxy_image():
    image_url = 'https://fastly.picsum.photos/id/937/800/600.jpg?hmac=3KZw8KGJxr0cyPeT6AwgAKH7sLIQEdRPnSwGKvNMyKY'
    response = requests.get(image_url)
    return response.content, response.status_code, {'Content-Type': response.headers['Content-Type']}

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)'''

import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, send
from datetime import datetime
from flask_cors import CORS  # For CORS handling
import requests  # For proxy routes
import re  # For input validation
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:suga@localhost/mental_health_prj'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
CORS(app)  # Enable CORS for all routes

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    community = db.Column(db.String(50), nullable=True)  # New: User community

# UserProfile Model
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    community = db.Column(db.String(50), nullable=False)
    bio = db.Column(db.Text)
    interests = db.Column(db.Text)
    profile_picture = db.Column(db.String(255))  # New field for profile picture path

    user = db.relationship('User', backref=db.backref('profile', uselist=False))


# Message Model for storing chat messages
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        community = request.form['community']
        bio = request.form.get('bio', '').strip()  # New: Get bio from form
        interests = request.form.get('interests', '').strip()  # New: Get interests from form

        # Input validation
        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Invalid username.', 'error')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, community=community)
        db.session.add(new_user)
        db.session.commit()

        # Create a profile for the new user
        new_profile = UserProfile(user_id=new_user.id, community=community, bio=bio, interests=interests)
        db.session.add(new_profile)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('dashboard.html', users=users)

# Matchmaking based on community
@app.route('/find_match')
@login_required
def find_match():
    matched_users = User.query.filter(User.community == current_user.community, User.id != current_user.id).all()
    return render_template('matches.html', matched_users=matched_users)

# Chat Route
@app.route('/chat/<username>')
@login_required
def chat(username):
    recipient = User.query.filter_by(username=username).first()
    if not recipient:
        flash('User does not exist.', 'error')
        return redirect(url_for('dashboard'))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    return render_template('community_sel.html', recipient=recipient, messages=messages)

# WebSocket for real-time messaging
@socketio.on('send_message')
def handle_send_message(data):
    sender = current_user.username
    receiver = data['receiver']
    message = data['message'].strip()

    if message:
        receiver_user = User.query.filter_by(username=receiver).first()
        new_message = Message(sender_id=current_user.id, receiver_id=receiver_user.id, message=message)
        db.session.add(new_message)
        db.session.commit()

        send({'sender': sender, 'message': message}, room=receiver)

# CORS Proxy for external APIs
@app.route('/proxy/quote')
def proxy_quote():
    response = requests.get('https://api.quotable.io/random')
    return jsonify(response.json())

@app.route('/proxy/image')
def proxy_image():
    image_url = 'https://fastly.picsum.photos/id/937/800/600.jpg?hmac=3KZw8KGJxr0cyPeT6AwgAKH7sLIQEdRPnSwGKvNMyKY'
    response = requests.get(image_url)
    return response.content, response.status_code, {'Content-Type': response.headers['Content-Type']}

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Profile Route - Fetch and Update Profile
'''@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        interests = request.form.get('interests', '').strip()
        profile_picture = request.files.get('profile_picture')

        # Fetch the user's profile
        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

        # If the profile doesn't exist, create one
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id)

        # Update profile fields
        user_profile.bio = bio
        user_profile.interests = interests

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(filepath)
            user_profile.profile_picture = filename  # Save file path in the database

        db.session.add(user_profile)
        db.session.commit()

        flash('Profile updated successfully!', 'success')

# Fetch the updated profile data
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', profile=user_profile) 


    # Fetch profile data
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', profile=user_profile)
'''


# Profile Route - Fetch and Update Profile
# Profile Route - Fetch and Update Profile
# Profile Route - Fetch and Update Profile
'''@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        interests = request.form.get('interests', '').strip()
        profile_picture = request.files.get('profile_picture')

        # Fetch the user's profile
        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

        # If the profile doesn't exist, create one
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id)

        # Update profile fields
        user_profile.bio = bio
        user_profile.interests = interests

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture if it exists
            if user_profile.profile_picture:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_profile.profile_picture)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            # Save new profile picture
            filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(filepath)
            user_profile.profile_picture = filename  # Save file path in the database

        # Save changes to database
        db.session.add(user_profile)
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))



    # Fetch profile data
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', profile=user_profile)
'''

'''@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        interests = request.form.get('interests', '').strip()
        profile_picture = request.files.get('profile_picture')

        # Fetch the user's profile
        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

        # If the profile doesn't exist, create one
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
            db.session.add(user_profile)
        else:
            # Update profile fields
            user_profile.bio = bio
            user_profile.interests = interests

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture if it exists
            if user_profile.profile_picture:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_profile.profile_picture)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            # Save new profile picture
            filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(filepath)
            user_profile.profile_picture = filename  # Save file path in the database

        # Save changes to database
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Fetch profile data
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', profile=user_profile)


'''





@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Fetch the profile of the currently logged-in user
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        interests = request.form.get('interests', '').strip()
        profile_picture = request.files.get('profile_picture')

        # If the profile doesn't exist, create one
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
            db.session.add(user_profile)
        else:
            # Update profile fields
            user_profile.bio = bio
            user_profile.interests = interests

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture if it exists
            if user_profile.profile_picture:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_profile.profile_picture)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            # Save new profile picture
            filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(filepath)
            user_profile.profile_picture = filename  # Save file path in the database

        # Save changes to the database
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Render the profile template with the current user's profile data
    return render_template('profile.html', profile=user_profile)

'''@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    bio = data.get('bio', '').strip()
    interests = data.get('interests', '').strip()

    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    if not user_profile:
        user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
        db.session.add(user_profile)
    else:
        user_profile.bio = bio
        user_profile.interests = interests

    print("Received Data:", data)  # Debugging line    

    db.session.commit()
    return jsonify({"success": True})
'''



@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    bio = data.get('bio', '').strip()
    interests = data.get('interests', '').strip()

    # Fetch the user's profile if it exists
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if user_profile:  
        # ✅ Only update if values have changed
        if user_profile.bio != bio or user_profile.interests != interests:
            user_profile.bio = bio
            user_profile.interests = interests
            db.session.commit()
            print(f"✅ Updated profile for user {current_user.id}: Bio - {bio}, Interests - {interests}")
        else:
            print(f"ℹ️ No changes detected for user {current_user.id}. Skipping update.")
    else:
        # ✅ Create new profile if it doesn't exist
        user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
        db.session.add(user_profile)
        db.session.commit()
        print(f"✅ Created new profile for user {current_user.id}")

    return jsonify({"success": True})

@app.route('/update_profile_picture', methods=['POST'])
@login_required
def update_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    profile_picture = request.files['profile_picture']
    if profile_picture and allowed_file(profile_picture.filename):
        filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_picture.save(filepath)

        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id)
            db.session.add(user_profile)
        user_profile.profile_picture = filename
        db.session.commit()



        return jsonify({"success": True, "profile_picture_url": url_for('static', filename=f"uploads/{filename}")})

    return jsonify({"success": False, "error": "Invalid file type"})

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)