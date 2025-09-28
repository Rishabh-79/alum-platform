from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mcc_alumni_secret_key_2024_enhanced'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mcc_alumni.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'student' or 'alumni'
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

    @property
    def comment_count(self):
        return len(self.comments)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Helper functions
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to access this page.')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    # Get recent posts for homepage preview
    recent_posts = Post.query.order_by(Post.date_created.desc()).limit(3).all()
    total_users = User.query.count()
    total_posts = Post.query.count()
    total_comments = Comment.query.count()

    return render_template('index.html', 
                         recent_posts=recent_posts,
                         stats={'users': total_users, 'posts': total_posts, 'comments': total_comments})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user_type = request.form.get('user_type', '')

        # Validation
        if not all([name, email, password, user_type]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered! Please use a different email or sign in.', 'error')
            return redirect(url_for('signup'))

        # Create new user
        try:
            password_hash = generate_password_hash(password)
            new_user = User(name=name, email=email, password_hash=password_hash, user_type=user_type)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please sign in with your credentials.', 'success')
            return redirect(url_for('signin'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating account. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return redirect(url_for('signin'))

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Set session
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_type'] = user.user_type
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_created.desc()).paginate(
        page=page, per_page=10, error_out=False)

    return render_template('dashboard.html', posts=posts.items, pagination=posts)

@app.route('/addpost', methods=['GET', 'POST'])
@login_required
def addpost():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        if not title or not description:
            flash('Both title and content are required!', 'error')
            return redirect(url_for('addpost'))

        if len(title) > 200:
            flash('Title must be less than 200 characters!', 'error')
            return redirect(url_for('addpost'))

        try:
            new_post = Post(
                title=title, 
                description=description, 
                author_name=session['user_name'],
                user_id=session['user_id']
            )
            db.session.add(new_post)
            db.session.commit()
            flash('Post created successfully!', 'success')
            return redirect(url_for('viewpost', post_id=new_post.id))
        except Exception as e:
            db.session.rollback()
            flash('Error creating post. Please try again.', 'error')
            return redirect(url_for('addpost'))

    return render_template('addpost.html')

@app.route('/viewpost/<int:post_id>', methods=['GET', 'POST'])
@login_required
def viewpost(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.date_created.asc()).all()

    if request.method == 'POST':
        content = request.form.get('content', '').strip()

        if not content:
            flash('Comment cannot be empty!', 'error')
            return redirect(url_for('viewpost', post_id=post_id))

        try:
            new_comment = Comment(
                content=content,
                author_name=session['user_name'],
                post_id=post_id,
                user_id=session['user_id']
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')
            return redirect(url_for('viewpost', post_id=post_id))
        except Exception as e:
            db.session.rollback()
            flash('Error adding comment. Please try again.', 'error')

    return render_template('viewpost.html', post=post, comments=comments)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Check if user owns the post
    if post.user_id != session['user_id']:
        flash('You can only edit your own posts.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        if not title or not description:
            flash('Both title and content are required!', 'error')
            return redirect(url_for('edit_post', post_id=post_id))

        try:
            post.title = title
            post.description = description
            post.date_updated = datetime.utcnow()
            db.session.commit()
            flash('Post updated successfully!', 'success')
            return redirect(url_for('viewpost', post_id=post_id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating post. Please try again.', 'error')

    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Check if user owns the post
    if post.user_id != session['user_id']:
        flash('You can only delete your own posts.', 'error')
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting post. Please try again.', 'error')

    return redirect(url_for('dashboard'))

@app.route('/my_posts')
@login_required
def my_posts():
    posts = Post.query.filter_by(user_id=session['user_id']).order_by(Post.date_created.desc()).all()
    return render_template('my_posts.html', posts=posts)

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    user_posts = Post.query.filter_by(user_id=session['user_id']).count()
    user_comments = Comment.query.filter_by(user_id=session['user_id']).count()

    return render_template('profile.html', user=user, post_count=user_posts, comment_count=user_comments)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# API endpoints
@app.route('/api/posts')
def api_posts():
    posts = Post.query.order_by(Post.date_created.desc()).limit(10).all()
    return jsonify([{
        'id': post.id,
        'title': post.title,
        'author': post.author_name,
        'date': post.date_created.strftime('%Y-%m-%d %H:%M:%S'),
        'comments': post.comment_count
    } for post in posts])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")
        print("Starting MCC Alumni Association Platform...")
        print("Open your browser to: http://localhost:5000")
    app.run(debug=True)