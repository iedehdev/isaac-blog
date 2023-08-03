from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import bleach
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
# if os.environ.get('LOCAL'):
#     app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
#     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# else:
#     app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')

db = SQLAlchemy(app)

# Setup LoginManager and configure flask app to use Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize Gravatar with flask application and default parameters
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    # return User.query.get(user_id)
    return db.get_or_404(User, user_id)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    posts = db.relationship('BlogPost', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='comment_author', lazy=True)

    def set_password(self, plain_text_password):
        self.password = generate_password_hash(plain_text_password, method='pbkdf2:sha256', salt_length=8)

    def check_password(self, plain_text_password):
        return check_password_hash(self.password, plain_text_password)

    def __repr__(self):
        return '<User{}>'.format(self.name)


class BlogPost(UserMixin, db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='parent_post')


class Comment(UserMixin, db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    comment_author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


with app.app_context():
    db.create_all()


## strips invalid tags/attributes
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

    return cleaned


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['GET'])
def get_all_posts():
    # posts = BlogPost.query.all()
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # print('registration started')
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        username = form.name.data

        # Check if user already exists
        # user = User.query.filter_by(email=email).first()
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            flash("You've already signed up with that email, login instead.")
            return redirect(url_for('login'))
        else:
            # print('New user being created.')
            new_user = User()
            new_user.name = username
            new_user.email = email
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            # Can redirect() and get name from the current_user
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # Check stored password hash against entered password hashed.
        if user.check_password(password):
            login_user(user)
            # flash('Logged in successfully.')
            return redirect(url_for('get_all_posts'))
        else:
            flash('Incorrect email or password, please try again.')
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    # requested_post = BlogPost.query.get(post_id)
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You must login to your account to comment.')
            return redirect(url_for('login'))

        new_comment = Comment()
        new_comment.text = strip_invalid_html(comment_form.comment_text.data)
        new_comment.comment_author_id = current_user.id
        new_comment.post_id = post_id

        db.session.add(new_comment)
        db.session.commit()
        comment_form.comment_text.data = ""

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=strip_invalid_html(form.body.data),
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        # new_post.title = form.title.data
        # new_post.subtitle = form.subtitle.data
        # new_post.body = strip_invalid_html(form.body.data)
        # new_post.img_url = form.img_url.data
        # new_post.author_id = current_user.id
        # new_post.date = date.today().strftime("%B %d, %Y")
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    # post = BlogPost.query.get(post_id)
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = strip_invalid_html(edit_form.body.data)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    # post_to_delete = BlogPost.query.get(post_id)
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)


