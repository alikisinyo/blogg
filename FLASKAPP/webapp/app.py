from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from os import path
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import sqlite3




app = Flask(__name__)


app.config["SECRET_KEY"] = 'test'
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///test.db'

db = SQLAlchemy(app)


# login_manager = LoginManager()
# login_manager.login_view = 'login'
# login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String)
    password = db.Column(db.String, unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.relationship('Post', backref='user', passive_deletes=True)
    
    def get_id(self):
        return str(self.id)
    
    def __repr__(self):
        return '<Name %r>' % self.id
    

    with app.app_context():
        db.create_all()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text =db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
        
    
login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None
    
with app.app_context():
    if not path.exists('webapp/{DB_NAME}'):
        db.create_all()
        print("Created database!")


@app.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category='success')
                login_user(user, remember=True)
                return render_template("home.html", title="Home")
            else:
                flash('Password is incorrect.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", title="Login User")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('Email is already in use.', category='error')
        elif username_exists:
            flash('Username is already in use.', category='error')
        elif password != password2:
            flash('Password don\'t match!', category='error')
        elif len(username) < 2:
            flash('Username is too short.', category='error')
        elif len(password) < 6:
            flash('Password is too short.', category='error')
        elif len(email) < 4:
            flash("Email is invalid.", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('User created!')
            return render_template("home.html", title="Home")

    return render_template("register.html", title="Register User")


@app.route("/home")
@login_required
def home():
    return render_template("home.html", title="bloRan")

@app.route("/tech")
@login_required
def tech():
    return render_template("tech.html", title="Tech-Hub")

@app.route("/malware")
@login_required
def malware():
    return render_template("malware.html", title="Mal-Hub")

@app.route("/educate", methods=['GET', 'POST'])
@login_required
def educate():
    posts = Post.query.all()
    return render_template("educate.html", title="Educate", user=current_user, posts=posts)

@app.route("/write", methods=['GET', 'POST'])
@login_required
def write():
    if request.method == "POST":
        text = request.form.get('text')

        if not text:
            flash("Post cannot be empty", category="error")
        else:
            post = Post(text=text, author=current_user.id)
            db.session.add(post)
            db.session.commit()
            flash("Post created", category="success")
            return redirect(url_for("educate"))

    return render_template("write.html", title="Write", user=current_user)

@app.route('/delete-post/<id>')
@login_required
def delete_post(id):
    post = Post.query.filter_by(id=id).first()

    if not post:
        flash("Post does not exist!", category="error")
    elif current_user.id != post.id:
        flash("You do not have permission to delete this post.", category="error")
    else:
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted!", category="success")
        
    return redirect(url_for('educate'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == "__main__":
    app.run(debug=True)